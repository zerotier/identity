/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * (c) ZeroTier, Inc.
 * https://www.zerotier.com/
 */

use std::alloc::{alloc, Layout};
use std::fmt::Debug;
use std::hash::Hash;
use std::io::{Read, Write};
use std::mem::transmute_copy;
use std::ptr::copy_nonoverlapping;
use std::str::FromStr;
use std::sync::Mutex;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use zerotier_crypto::hash::{SHA384, SHA512};
use zerotier_crypto::p384::{P384PublicKey, P384_ECDSA_SIGNATURE_SIZE, P384_PUBLIC_KEY_SIZE};
use zerotier_crypto::salsa::Salsa;
use zerotier_crypto::x25519::*;
use zerotier_utils::arrayvec::ArrayVec;
use zerotier_utils::error::InvalidParameterError;
use zerotier_utils::tofrombytes::ToFromBytes;
use zerotier_utils::{base64, hex, parallelism};

use crate::address::Address;
use crate::identitysecret::IdentitySecret;
use crate::signature::parse_signature;

pub const TYPE_NAME_X25519: &'static str = "x25519";
pub const TYPE_NAME_X25519P384: &'static str = "x25519p384";
pub const TYPE_NAME_P384: &'static str = "p384";

#[derive(Clone)]
pub enum Identity {
    // type 0 - legacy ZeroTier One identity
    X25519 {
        address: Address,
        x25519_ecdh: [u8; C25519_PUBLIC_KEY_SIZE],
        x25519_eddsa: [u8; ED25519_PUBLIC_KEY_SIZE],
    },
    // type 1 - p384 with legacy backward compatibility
    X25519P384 {
        address: Address,
        master_signing_key: P384PublicKey,
        timestamp: i64,
        x25519_ecdh: [u8; C25519_PUBLIC_KEY_SIZE],
        x25519_eddsa: [u8; ED25519_PUBLIC_KEY_SIZE],
        p384_ecdh: P384PublicKey,
        p384_ecdsa: P384PublicKey,
        x25519_signature: [u8; ED25519_SIGNATURE_SIZE],
        master_signature: [u8; P384_ECDSA_SIGNATURE_SIZE],
    },
    // type 2 - just p384, no legacy
    P384 {
        address: Address,
        master_signing_key: P384PublicKey,
        timestamp: i64,
        p384_ecdh: P384PublicKey,
        p384_ecdsa: P384PublicKey,
        master_signature: [u8; P384_ECDSA_SIGNATURE_SIZE],
    },
}

impl Identity {
    pub(crate) const LEGACY_ADDRESS_POW_THRESHOLD: u8 = 17;

    #[inline(always)]
    pub fn address(&self) -> &Address {
        match self {
            Self::X25519 { address, .. } | Self::X25519P384 { address, .. } | Self::P384 { address, .. } => address,
        }
    }

    /// Get a human readable name for this identity's type.
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::X25519 { .. } => TYPE_NAME_X25519,
            Self::X25519P384 { .. } => TYPE_NAME_X25519P384,
            Self::P384 { .. } => TYPE_NAME_P384,
        }
    }

    /// True if the first 5 bytes of this identity's address are a ZeroTier One compatible legacy short address.
    #[inline]
    pub fn is_legacy_compatible(&self) -> bool {
        matches!(self, Self::X25519 { .. } | Self::X25519P384 { .. })
    }

    /// True if this is a legacy-only identity
    #[inline]
    pub fn is_legacy_only(&self) -> bool {
        matches!(self, Self::X25519 { .. })
    }

    /// Write legacy ZeroTier One binary serialized identity (if this identity is backward compatible).
    #[cfg(feature = "legacy_zt1")]
    pub fn write_legacy_bytes<W: Write>(&self, w: &mut W) -> std::io::Result<()> {
        let (legacy_address, ecdh, eddsa) = match self {
            Self::X25519 { address, x25519_ecdh, x25519_eddsa } => (address.as_legacy_short_bytes(), x25519_ecdh, x25519_eddsa),
            Self::X25519P384 { address, x25519_ecdh, x25519_eddsa, .. } => (address.as_legacy_short_bytes(), x25519_ecdh, x25519_eddsa),
            _ => return Err(std::io::Error::new(std::io::ErrorKind::Other, "not a legacy compatible identity")),
        };
        w.write_all(legacy_address)?;
        w.write_all(&[0])?;
        w.write_all(ecdh)?;
        w.write_all(eddsa)?;
        w.write_all(&[0])
    }

    /// Read legacy ZeroTier One binary serialized identity.
    /// A secret is also returned if it is present in the stream.
    #[cfg(feature = "legacy_zt1")]
    pub fn read_legacy_bytes<R: Read>(r: &mut R) -> std::io::Result<(Self, Option<IdentitySecret>)> {
        let mut tmp = [0u8; Address::LEGACY_SHORT_SIZE + 1 + C25519_PUBLIC_KEY_SIZE + ED25519_PUBLIC_KEY_SIZE + 1];
        r.read_exact(&mut tmp)?;
        if tmp[Address::LEGACY_SHORT_SIZE] != 0 {
            return Err(std::io::Error::new(std::io::ErrorKind::Other, "invalid identity type"));
        }

        let x25519_ecdh: [u8; C25519_PUBLIC_KEY_SIZE] = tmp[Address::LEGACY_SHORT_SIZE + 1..Address::LEGACY_SHORT_SIZE + 1 + C25519_PUBLIC_KEY_SIZE]
            .try_into()
            .unwrap();
        let x25519_eddsa: [u8; ED25519_PUBLIC_KEY_SIZE] = tmp[Address::LEGACY_SHORT_SIZE + 1 + C25519_PUBLIC_KEY_SIZE
            ..Address::LEGACY_SHORT_SIZE + 1 + C25519_PUBLIC_KEY_SIZE + ED25519_PUBLIC_KEY_SIZE]
            .try_into()
            .unwrap();

        let public = Self::X25519 {
            address: {
                let mut address_hasher = SHA384::new();
                address_hasher.update(&x25519_ecdh);
                address_hasher.update(&x25519_eddsa);
                let mut address = Address(address_hasher.finish());
                address.0[..Address::LEGACY_SHORT_SIZE].copy_from_slice(&tmp[..Address::LEGACY_SHORT_SIZE]);
                address
            },
            x25519_ecdh,
            x25519_eddsa,
        };

        let secret_bytes = tmp[Address::LEGACY_SHORT_SIZE + 1 + C25519_PUBLIC_KEY_SIZE + ED25519_PUBLIC_KEY_SIZE];
        let secret = if secret_bytes == (C25519_SECRET_KEY_SIZE + ED25519_SECRET_KEY_SIZE) as u8 {
            r.read_exact(&mut tmp[..C25519_SECRET_KEY_SIZE + ED25519_SECRET_KEY_SIZE])?;
            Some(IdentitySecret {
                public: public.clone(),
                secret: crate::identitysecret::SecretKeys::X25519 {
                    x25519_ecdh: X25519KeyPair::from_bytes(&x25519_ecdh, &tmp[..C25519_SECRET_KEY_SIZE])
                        .ok_or(std::io::Error::new(std::io::ErrorKind::Other, "invalid key"))?,
                    x25519_eddsa: Ed25519KeyPair::from_bytes(
                        &x25519_eddsa,
                        &tmp[C25519_SECRET_KEY_SIZE..C25519_SECRET_KEY_SIZE + ED25519_SECRET_KEY_SIZE],
                    )
                    .ok_or(std::io::Error::new(std::io::ErrorKind::Other, "invalid key"))?,
                },
            })
        } else if secret_bytes != 0 {
            return Err(std::io::Error::new(std::io::ErrorKind::Other, "invalid key"));
        } else {
            None
        };

        if public.internal_validate() {
            return Ok((public, secret));
        } else {
            return Err(std::io::Error::new(std::io::ErrorKind::Other, "invalid identity"));
        }
    }

    /// Get NIST P-384 ECDH and ECDSA public keys if present.
    pub fn p384(&self) -> Option<(&P384PublicKey, &P384PublicKey)> {
        match self {
            Self::X25519P384 { p384_ecdh, p384_ecdsa, .. } => Some((p384_ecdh, p384_ecdsa)),
            Self::P384 { p384_ecdh, p384_ecdsa, .. } => Some((p384_ecdh, p384_ecdsa)),
            _ => None,
        }
    }

    /// Get x25519 ECDH and EDDSA public keys if present.
    pub fn x25519(&self) -> Option<(&[u8; C25519_PUBLIC_KEY_SIZE], &[u8; ED25519_PUBLIC_KEY_SIZE])> {
        match self {
            Self::X25519 { x25519_ecdh, x25519_eddsa, .. } => Some((x25519_ecdh, x25519_eddsa)),
            Self::X25519P384 { x25519_ecdh, x25519_eddsa, .. } => Some((x25519_ecdh, x25519_eddsa)),
            _ => None,
        }
    }

    /// Verify a legacy ZeroTier One signature (if we have x25519 keys).
    pub fn verify_legacy(&self, signature: &[u8], data: &[u8]) -> bool {
        if signature.len() == 64 || signature.len() == 96 {
            match self {
                Self::X25519 { x25519_eddsa, .. } => return ed25519_verify(x25519_eddsa, signature, data),
                Self::X25519P384 { x25519_eddsa, .. } => return ed25519_verify(x25519_eddsa, signature, data),
                _ => return false,
            }
        } else {
            return false;
        }
    }

    /// Verify a signature.
    pub fn verify(&self, signature: &[u8], data: &[u8]) -> bool {
        let (p384_sig, x25519_sig) = parse_signature(signature);
        match self {
            Self::X25519 { x25519_eddsa, .. } => {
                if let Some(x25519_sig) = x25519_sig.as_ref() {
                    ed25519_verify(x25519_eddsa, x25519_sig, data)
                } else {
                    false
                }
            }
            Self::X25519P384 { x25519_eddsa, p384_ecdsa, .. } => {
                if let (Some(p384_sig), Some(x25519_sig)) = (p384_sig, x25519_sig) {
                    p384_ecdsa.verify(data, p384_sig) && ed25519_verify(x25519_eddsa, x25519_sig, data)
                } else {
                    false
                }
            }
            Self::P384 { p384_ecdsa, .. } => {
                if let Some(p384_sig) = p384_sig {
                    p384_ecdsa.verify(data, p384_sig)
                } else {
                    false
                }
            }
        }
    }

    /// Called internally on all code paths that return an Identity from deserialization, from_str(), etc.
    fn internal_validate(&self) -> bool {
        let mut legacy_address_hash = None;
        let mut master_signed = ArrayVec::<u8, 512>::new();

        let (address, mut address_should_be) = match self {
            Self::X25519 { address, x25519_ecdh, x25519_eddsa } => {
                let mut address_hasher = SHA384::new();
                address_hasher.update(x25519_ecdh);
                address_hasher.update(x25519_eddsa);

                let mut legacy_address_hasher = SHA512::new();
                legacy_address_hasher.update(x25519_ecdh);
                legacy_address_hasher.update(x25519_eddsa);
                let _ = legacy_address_hash.insert(legacy_address_hasher.finish());

                (address, address_hasher.finish())
            }
            Self::X25519P384 {
                address,
                master_signing_key,
                timestamp,
                x25519_ecdh,
                x25519_eddsa,
                p384_ecdh,
                p384_ecdsa,
                x25519_signature,
                master_signature,
            } => {
                if !ed25519_verify(x25519_eddsa, x25519_signature, master_signing_key.as_bytes()) {
                    return false;
                }

                master_signed.push_slice(&address.0);
                master_signed.push_slice(&timestamp.to_be_bytes());
                master_signed.push_slice(x25519_ecdh);
                master_signed.push_slice(x25519_eddsa);
                master_signed.push_slice(p384_ecdh.as_bytes());
                master_signed.push_slice(p384_ecdsa.as_bytes());
                master_signed.push_slice(x25519_signature);
                if !master_signing_key.verify(master_signed.as_ref(), master_signature) {
                    return false;
                }

                let mut legacy_address_hasher = SHA512::new();
                legacy_address_hasher.update(x25519_ecdh);
                legacy_address_hasher.update(x25519_eddsa);
                let _ = legacy_address_hash.insert(legacy_address_hasher.finish());

                (address, SHA384::hash(master_signing_key.as_bytes()))
            }
            Self::P384 {
                address,
                master_signing_key,
                timestamp,
                p384_ecdh,
                p384_ecdsa,
                master_signature,
            } => {
                master_signed.push_slice(&address.0);
                master_signed.push_slice(&timestamp.to_be_bytes());
                master_signed.push_slice(p384_ecdh.as_bytes());
                master_signed.push_slice(p384_ecdsa.as_bytes());
                if !master_signing_key.verify(master_signed.as_ref(), master_signature) {
                    return false;
                }

                (address, SHA384::hash(master_signing_key.as_bytes()))
            }
        };

        if let Some(legacy_address_hash) = legacy_address_hash.as_mut() {
            // Check the part of the address that does not require computation of the work function first,
            // since this saves time in the obviously corrupt case.
            if !address_should_be[Address::LEGACY_SHORT_SIZE..].eq(&address.0[Address::LEGACY_SHORT_SIZE..]) {
                return false;
            }

            legacy_address_derivation_work_function(legacy_address_hash);
            if legacy_address_hash[0] >= Self::LEGACY_ADDRESS_POW_THRESHOLD || legacy_address_hash[59] == Address::LEGACY_RESERVED_PREFIX {
                return false;
            }
            address_should_be[..Address::LEGACY_SHORT_SIZE].copy_from_slice(&legacy_address_hash[59..64]);
        }

        return address.0.eq(&address_should_be);
    }
}

impl ToString for Identity {
    fn to_string(&self) -> String {
        let (address, type_name) = match self {
            Self::X25519 { address, x25519_ecdh, x25519_eddsa } => {
                // For type 0 output the identity in legacy compatible string format
                return format!(
                    "{}:0:{}{}",
                    address.to_legacy_short_string(),
                    hex::to_string(x25519_ecdh),
                    hex::to_string(x25519_eddsa)
                );
            }
            Self::X25519P384 { address, .. } => (address, TYPE_NAME_X25519P384),
            Self::P384 { address, .. } => (address, TYPE_NAME_P384),
        };
        return format!(
            "{}:{}:{}",
            address.to_string(),
            type_name,
            base64::to_string(self.to_bytes_on_stack::<16384>().as_ref())
        );
    }
}

impl FromStr for Identity {
    type Err = InvalidParameterError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut fi = s.split(':');
        let address_str = fi.next().ok_or(InvalidParameterError("incomplete"))?;
        let type_str = fi.next().ok_or(InvalidParameterError("incomplete"))?;
        let data_str = fi.next().ok_or(InvalidParameterError("incomplete"))?;

        if type_str == "0" {
            let keys = hex::from_string(data_str);
            if keys.len() == (C25519_PUBLIC_KEY_SIZE + ED25519_PUBLIC_KEY_SIZE) {
                let mut address_hasher = SHA384::new();
                address_hasher.update(keys.as_slice());
                let mut address = Address::from_legacy_short_string(address_str)?;
                address.0[Address::LEGACY_SHORT_SIZE..].copy_from_slice(&address_hasher.finish()[Address::LEGACY_SHORT_SIZE..]);

                let id = Self::X25519 {
                    address,
                    x25519_ecdh: keys[..C25519_PUBLIC_KEY_SIZE].try_into().unwrap(),
                    x25519_eddsa: keys[C25519_PUBLIC_KEY_SIZE..].try_into().unwrap(),
                };

                if !id.internal_validate() {
                    return Err(InvalidParameterError("invalid identity"));
                }

                return Ok(id);
            } else {
                return Err(InvalidParameterError("invalid key"));
            }
        } else {
            let id = Self::from_bytes(
                base64::from_string(data_str.trim().as_bytes())
                    .ok_or(InvalidParameterError("invalid base64"))?
                    .as_slice(),
            )
            .map_err(|_| InvalidParameterError("invalid serialized data"))?;
            if !id.address().eq(&Address::from_str(address_str)?) {
                return Err(InvalidParameterError("invalid address"));
            }
            // The deserializer (via from_bytes()) will already have internally validated the identity.
            return Ok(id);
        }
    }
}

impl Debug for Identity {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.to_string().as_str())
    }
}

impl ToFromBytes for Identity {
    fn read_bytes<R: std::io::Read>(r: &mut R) -> std::io::Result<Self> {
        let mut tmp = [0u8; 512];
        r.read_exact(&mut tmp[..1])?;
        let id = match tmp[0] {
            0 => {
                r.read_exact(&mut tmp[..Address::SIZE + C25519_PUBLIC_KEY_SIZE + ED25519_PUBLIC_KEY_SIZE])?;
                Identity::X25519 {
                    address: Address(tmp[..Address::SIZE].try_into().unwrap()),
                    x25519_ecdh: tmp[Address::SIZE..Address::SIZE + C25519_PUBLIC_KEY_SIZE].try_into().unwrap(),
                    x25519_eddsa: tmp[Address::SIZE + C25519_PUBLIC_KEY_SIZE..Address::SIZE + C25519_PUBLIC_KEY_SIZE + ED25519_PUBLIC_KEY_SIZE]
                        .try_into()
                        .unwrap(),
                }
            }
            1 => {
                const F0: usize = Address::SIZE;
                const F1: usize = F0 + P384_PUBLIC_KEY_SIZE;
                const F2: usize = F1 + 8;
                const F3: usize = F2 + C25519_PUBLIC_KEY_SIZE;
                const F4: usize = F3 + ED25519_PUBLIC_KEY_SIZE;
                const F5: usize = F4 + P384_PUBLIC_KEY_SIZE;
                const F6: usize = F5 + P384_PUBLIC_KEY_SIZE;
                const F7: usize = F6 + ED25519_SIGNATURE_SIZE;
                const F8: usize = F7 + P384_ECDSA_SIGNATURE_SIZE;
                r.read_exact(&mut tmp[..F8])?;
                Identity::X25519P384 {
                    address: Address(tmp[..F0].try_into().unwrap()),
                    master_signing_key: P384PublicKey::from_bytes(&tmp[F0..F1])
                        .ok_or(std::io::Error::new(std::io::ErrorKind::Other, "invalid key"))?,
                    timestamp: i64::from_be_bytes(tmp[F1..F2].try_into().unwrap()),
                    x25519_ecdh: tmp[F2..F3].try_into().unwrap(),
                    x25519_eddsa: tmp[F3..F4].try_into().unwrap(),
                    p384_ecdh: P384PublicKey::from_bytes(&tmp[F4..F5]).ok_or(std::io::Error::new(std::io::ErrorKind::Other, "invalid key"))?,
                    p384_ecdsa: P384PublicKey::from_bytes(&tmp[F5..F6]).ok_or(std::io::Error::new(std::io::ErrorKind::Other, "invalid key"))?,
                    x25519_signature: tmp[F6..F7].try_into().unwrap(),
                    master_signature: tmp[F7..F8].try_into().unwrap(),
                }
            }
            2 => {
                const F0: usize = Address::SIZE;
                const F1: usize = F0 + P384_PUBLIC_KEY_SIZE;
                const F2: usize = F1 + 8;
                const F3: usize = F2 + P384_PUBLIC_KEY_SIZE;
                const F4: usize = F3 + P384_PUBLIC_KEY_SIZE;
                const F5: usize = F4 + P384_ECDSA_SIGNATURE_SIZE;
                r.read_exact(&mut tmp[..F5])?;
                Identity::P384 {
                    address: Address(tmp[..F0].try_into().unwrap()),
                    master_signing_key: P384PublicKey::from_bytes(&tmp[F0..F1])
                        .ok_or(std::io::Error::new(std::io::ErrorKind::Other, "invalid key"))?,
                    timestamp: i64::from_be_bytes(tmp[F1..F2].try_into().unwrap()),
                    p384_ecdh: P384PublicKey::from_bytes(&tmp[F2..F3]).ok_or(std::io::Error::new(std::io::ErrorKind::Other, "invalid key"))?,
                    p384_ecdsa: P384PublicKey::from_bytes(&tmp[F3..F4]).ok_or(std::io::Error::new(std::io::ErrorKind::Other, "invalid key"))?,
                    master_signature: tmp[F4..F5].try_into().unwrap(),
                }
            }
            _ => return Err(std::io::Error::new(std::io::ErrorKind::Other, "unsupported identity type")),
        };
        if !id.internal_validate() {
            return Err(std::io::Error::new(std::io::ErrorKind::Other, "invalid identity"));
        }
        return Ok(id);
    }

    fn write_bytes<W: Write>(&self, w: &mut W) -> std::io::Result<()> {
        match self {
            Identity::X25519 { address, x25519_ecdh, x25519_eddsa } => {
                w.write_all(&[0u8])?;
                w.write_all(&address.0)?;
                w.write_all(x25519_ecdh)?;
                w.write_all(x25519_eddsa)?;
            }
            Identity::X25519P384 {
                address,
                master_signing_key,
                timestamp,
                x25519_ecdh,
                x25519_eddsa,
                p384_ecdh,
                p384_ecdsa,
                x25519_signature,
                master_signature,
            } => {
                w.write_all(&[1u8])?;
                w.write_all(&address.0)?;
                w.write_all(master_signing_key.as_bytes())?;
                w.write_all(&timestamp.to_be_bytes())?;
                w.write_all(x25519_ecdh)?;
                w.write_all(x25519_eddsa)?;
                w.write_all(p384_ecdh.as_bytes())?;
                w.write_all(p384_ecdsa.as_bytes())?;
                w.write_all(x25519_signature)?;
                w.write_all(master_signature)?;
            }
            Identity::P384 {
                address,
                master_signing_key,
                timestamp,
                p384_ecdh,
                p384_ecdsa,
                master_signature,
            } => {
                w.write_all(&[2u8])?;
                w.write_all(&address.0)?;
                w.write_all(master_signing_key.as_bytes())?;
                w.write_all(&timestamp.to_be_bytes())?;
                w.write_all(p384_ecdh.as_bytes())?;
                w.write_all(p384_ecdsa.as_bytes())?;
                w.write_all(master_signature)?;
            }
        }
        Ok(())
    }
}

impl Serialize for Identity {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            self.to_string().serialize(serializer)
        } else {
            serializer.serialize_bytes(self.to_bytes_on_stack::<8192>().as_bytes())
        }
    }
}

struct IdentityDeserializeVisitor;

impl<'de> serde::de::Visitor<'de> for IdentityDeserializeVisitor {
    type Value = Identity;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("ZeroTier identity")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Identity::from_bytes(v).map_err(|e| serde::de::Error::custom(e.to_string()))
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Identity::from_str(v).map_err(|e| serde::de::Error::custom(e.to_string()))
    }
}

impl<'de> Deserialize<'de> for Identity {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            deserializer.deserialize_str(IdentityDeserializeVisitor)
        } else {
            deserializer.deserialize_bytes(IdentityDeserializeVisitor)
        }
    }
}

impl PartialEq for Identity {
    #[inline(always)]
    fn eq(&self, other: &Self) -> bool {
        self.address().eq(other.address())
    }
}

impl Eq for Identity {}

impl PartialOrd for Identity {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Identity {
    #[inline]
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.address().cmp(other.address())
    }
}

impl Hash for Identity {
    #[inline]
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.address().hash(state)
    }
}

// This is the memory-intensive hash used for address derivation in ZeroTier v1
pub(crate) fn legacy_address_derivation_work_function(digest_bytes: &mut [u8; 64]) {
    const ADDRESS_DERIVATION_HASH_MEMORY_SIZE: usize = 2097152;
    const ADDRESS_DERIVATION_HASH_MEMORY_SIZE_U64: usize = 2097152 / 8;

    static ADDRESS_DERIVATION_HASH_MEMORY: Mutex<Vec<Box<[u64; ADDRESS_DERIVATION_HASH_MEMORY_SIZE_U64]>>> = Mutex::new(Vec::new());

    let genmem = ADDRESS_DERIVATION_HASH_MEMORY.lock().unwrap().pop();
    let mut genmem =
        genmem.unwrap_or_else(|| unsafe { Box::from_raw(alloc(Layout::new::<[u64; ADDRESS_DERIVATION_HASH_MEMORY_SIZE_U64]>()).cast()) });

    let mut salsa: Salsa<20> = Salsa::new(&digest_bytes[..32], &digest_bytes[32..40]);
    genmem[..8].fill(0);
    salsa.crypt_in_place(unsafe { &mut *genmem.as_mut_ptr().cast::<[u8; 64]>() });
    let mut k = 0;
    while k < (ADDRESS_DERIVATION_HASH_MEMORY_SIZE - 64) {
        let kk = k + 64;
        unsafe {
            salsa.crypt(
                &*genmem.as_ptr().cast::<u8>().add(k).cast::<[u8; 64]>(),
                &mut *genmem.as_mut_ptr().cast::<u8>().add(kk).cast::<[u8; 64]>(),
            );
        }
        k = kk;
    }

    let mut digest: [u64; 8] = unsafe { transmute_copy(digest_bytes) };
    let mut i = 0;
    while i < ADDRESS_DERIVATION_HASH_MEMORY_SIZE_U64 {
        unsafe {
            let idx1 = ((*genmem.as_mut_ptr().cast::<u8>().add((i * 8) + 7)) & 7) as usize;
            let idx2 = (u64::from_be(*genmem.get_unchecked(i + 1)) as usize) % ADDRESS_DERIVATION_HASH_MEMORY_SIZE_U64;
            i += 2;
            debug_assert!(idx1 < digest.len());
            debug_assert!(idx2 < genmem.len());
            let genmem_idx2 = genmem.get_unchecked_mut(idx2);
            let digest_idx1 = digest.get_unchecked_mut(idx1);
            let tmp = *genmem_idx2;
            *genmem_idx2 = *digest_idx1;
            *digest_idx1 = tmp;
            salsa.crypt_in_place(&mut *digest.as_mut_ptr().cast::<[u8; 64]>());
        }
    }

    {
        let mut m = ADDRESS_DERIVATION_HASH_MEMORY.lock().unwrap();
        if m.len() < parallelism() {
            m.push(genmem);
        }
    }

    unsafe { copy_nonoverlapping(digest.as_ptr().cast::<u8>(), digest_bytes.as_mut_ptr(), 64) };
}
