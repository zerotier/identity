/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * (c) ZeroTier, Inc.
 * https://www.zerotier.com/
 */

use std::io::Write;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use zerotier_crypto::hash::{SHA384, SHA512};
use zerotier_crypto::p384::{P384KeyPair, P384_SECRET_KEY_SIZE};
use zerotier_crypto::x25519::*;
use zerotier_utils::arrayvec::ArrayVec;
use zerotier_utils::error::InvalidParameterError;
use zerotier_utils::tofrombytes::ToFromBytes;
use zerotier_utils::{base64, hex};

use crate::address::Address;
use crate::identity::{self, legacy_address_derivation_work_function, Identity};
use crate::signature::{make_signature, Signature};

pub struct IdentitySecret {
    pub public: Identity,
    pub(crate) secret: SecretKeys,
}

pub(crate) enum SecretKeys {
    X25519 {
        x25519_ecdh: X25519KeyPair,
        x25519_eddsa: Ed25519KeyPair,
    },
    X25519P384 {
        master_signing_key: Option<P384KeyPair>,
        x25519_ecdh: X25519KeyPair,
        x25519_eddsa: Ed25519KeyPair,
        p384_ecdh: P384KeyPair,
        p384_ecdsa: P384KeyPair,
    },
    P384 {
        master_signing_key: Option<P384KeyPair>,
        p384_ecdh: P384KeyPair,
        p384_ecdsa: P384KeyPair,
    },
}

impl IdentitySecret {
    /// Generate a legacy-only X25519 ZeroTier One identity.
    pub fn generate_x25519() -> Self {
        let (legacy_address, ecdh, eddsa) = Self::generate_legacy_x25519();
        let x25519_ecdh = ecdh.public_bytes();
        let x25519_eddsa = eddsa.public_bytes();

        return Self {
            public: Identity::X25519 {
                address: {
                    let mut address = Address::new_uninit();
                    let mut h = SHA384::new();
                    h.update(&x25519_ecdh);
                    h.update(&x25519_eddsa);
                    address.0 = h.finish();
                    address.0[..Address::LEGACY_SHORT_SIZE].copy_from_slice(&legacy_address);
                    address
                },
                x25519_ecdh,
                x25519_eddsa,
            },
            secret: SecretKeys::X25519 { x25519_ecdh: ecdh, x25519_eddsa: eddsa },
        };
    }

    /// Generate a hybrid backward compatible identity.
    /// If upgrade_from is not None it must contain a legacy x25519 type identity.
    pub fn generate_x25519p384(timestamp: i64, upgrade_from: Option<IdentitySecret>) -> Result<Self, InvalidParameterError> {
        let (legacy_address, x25519_ecdh_secret, x25519_eddsa_secret) = if let Some(upgrade_from) = upgrade_from {
            match upgrade_from {
                IdentitySecret {
                    public: Identity::X25519 { address, .. },
                    secret: SecretKeys::X25519 { x25519_ecdh, x25519_eddsa },
                } => (address.0[..Address::LEGACY_SHORT_SIZE].try_into().unwrap(), x25519_ecdh, x25519_eddsa),
                _ => {
                    return Err(InvalidParameterError("upgrade only allowed from X25519 to X25519P384"));
                }
            }
        } else {
            Self::generate_legacy_x25519()
        };

        let master_signing_key_secret = P384KeyPair::generate();
        let p384_ecdh_secret = P384KeyPair::generate();
        let p384_ecdsa_secret = P384KeyPair::generate();

        let x25519_ecdh = x25519_ecdh_secret.public_bytes();
        let x25519_eddsa = x25519_eddsa_secret.public_bytes();
        let x25519_signature = x25519_eddsa_secret.sign(master_signing_key_secret.public_key_bytes());

        let mut address = Address(SHA384::hash(master_signing_key_secret.public_key_bytes()));
        address.0[..Address::LEGACY_SHORT_SIZE].copy_from_slice(&legacy_address);

        let mut master_signed = ArrayVec::<u8, 512>::new();
        master_signed.push_slice(&address.0);
        master_signed.push_slice(&timestamp.to_be_bytes());
        master_signed.push_slice(&x25519_ecdh);
        master_signed.push_slice(&x25519_eddsa);
        master_signed.push_slice(p384_ecdh_secret.public_key_bytes());
        master_signed.push_slice(p384_ecdsa_secret.public_key_bytes());
        master_signed.push_slice(&x25519_signature);

        return Ok(Self {
            public: Identity::X25519P384 {
                address,
                master_signing_key: master_signing_key_secret.to_public_key(),
                timestamp,
                x25519_ecdh,
                x25519_eddsa,
                p384_ecdh: p384_ecdh_secret.to_public_key(),
                p384_ecdsa: p384_ecdsa_secret.to_public_key(),
                x25519_signature,
                master_signature: master_signing_key_secret.sign(master_signed.as_ref()),
            },
            secret: SecretKeys::X25519P384 {
                master_signing_key: Some(master_signing_key_secret),
                x25519_ecdh: x25519_ecdh_secret,
                x25519_eddsa: x25519_eddsa_secret,
                p384_ecdh: p384_ecdh_secret,
                p384_ecdsa: p384_ecdsa_secret,
            },
        });
    }

    /// Generate a new format P-384 identity without backward compatibility.
    pub fn generate_p384(timestamp: i64) -> Self {
        let master_signing_key_secret = P384KeyPair::generate();
        let p384_ecdh_secret = P384KeyPair::generate();
        let p384_ecdsa_secret = P384KeyPair::generate();

        let address = Address(SHA384::hash(master_signing_key_secret.public_key_bytes()));

        let mut master_signed = ArrayVec::<u8, 512>::new();
        master_signed.push_slice(&address.0);
        master_signed.push_slice(&timestamp.to_be_bytes());
        master_signed.push_slice(p384_ecdh_secret.public_key_bytes());
        master_signed.push_slice(p384_ecdsa_secret.public_key_bytes());

        return Self {
            public: Identity::P384 {
                address,
                master_signing_key: master_signing_key_secret.to_public_key(),
                timestamp,
                p384_ecdh: p384_ecdh_secret.to_public_key(),
                p384_ecdsa: p384_ecdsa_secret.to_public_key(),
                master_signature: master_signing_key_secret.sign(master_signed.as_ref()),
            },
            secret: SecretKeys::P384 {
                master_signing_key: Some(master_signing_key_secret),
                p384_ecdh: p384_ecdh_secret,
                p384_ecdsa: p384_ecdsa_secret,
            },
        };
    }

    fn generate_legacy_x25519() -> ([u8; Address::LEGACY_SHORT_SIZE], X25519KeyPair, Ed25519KeyPair) {
        let mut ecdh = X25519KeyPair::generate();
        let eddsa = Ed25519KeyPair::generate();
        let mut legacy_address_hasher = SHA512::new();
        loop {
            legacy_address_hasher.update(&ecdh.public_bytes());
            legacy_address_hasher.update(&eddsa.public_bytes());
            let mut legacy_address_hash = legacy_address_hasher.finish();
            legacy_address_derivation_work_function(&mut legacy_address_hash);
            if legacy_address_hash[0] < Identity::LEGACY_ADDRESS_POW_THRESHOLD
                && legacy_address_hash[59] != Address::LEGACY_RESERVED_PREFIX
                && legacy_address_hash[59..64].iter().any(|i| *i != 0)
            {
                return (legacy_address_hash[59..64].try_into().unwrap(), ecdh, eddsa);
            } else {
                ecdh = X25519KeyPair::generate();
                legacy_address_hasher.reset();
            }
        }
    }

    /// Get NIST P-384 ECDH and ECDSA key pairs if present.
    pub fn p384(&self) -> Option<(&P384KeyPair, &P384KeyPair)> {
        match self {
            Self {
                public: identity::Identity::X25519P384 { .. },
                secret: SecretKeys::X25519P384 { p384_ecdh, p384_ecdsa, .. },
            } => Some((p384_ecdh, p384_ecdsa)),
            Self {
                public: identity::Identity::P384 { .. },
                secret: SecretKeys::P384 { p384_ecdh, p384_ecdsa, .. },
            } => Some((p384_ecdh, p384_ecdsa)),
            _ => None,
        }
    }

    /// Get X25519 ECDH and EDDSA key pairs if present.
    pub fn x25519(&self) -> Option<(&X25519KeyPair, &Ed25519KeyPair)> {
        match self {
            Self {
                public: identity::Identity::X25519 { .. },
                secret: SecretKeys::X25519 { x25519_ecdh, x25519_eddsa, .. },
            } => Some((x25519_ecdh, x25519_eddsa)),
            Self {
                public: identity::Identity::X25519P384 { .. },
                secret: SecretKeys::X25519P384 { x25519_ecdh, x25519_eddsa, .. },
            } => Some((x25519_ecdh, x25519_eddsa)),
            _ => None,
        }
    }

    /// Sign a message using all available keys for this identity.
    pub fn sign(&self, data: &[u8]) -> Signature {
        match self {
            Self {
                public: identity::Identity::X25519 { .. },
                secret: SecretKeys::X25519 { x25519_eddsa, .. },
            } => make_signature(&[], &x25519_eddsa.sign(data)),
            Self {
                public: identity::Identity::X25519P384 { .. },
                secret: SecretKeys::X25519P384 { p384_ecdsa, x25519_eddsa, .. },
            } => make_signature(&p384_ecdsa.sign(data), &x25519_eddsa.sign(data)),
            Self {
                public: identity::Identity::P384 { .. },
                secret: SecretKeys::P384 { p384_ecdsa, .. },
            } => make_signature(&p384_ecdsa.sign(data), &[]),
            _ => panic!("IdentitySecret in invalid state (public/secret type mismatch)"),
        }
    }

    /// If the master signing key secret is included in this identity secret, remove and return it.
    /// If this is a legacy identity or the key is not present, this does nothing.
    /// This can be used to remove the master signing key from the secret for cold storage, returning
    /// a secret that is fully usable as such but that lacks the secret part of the master key.
    pub fn detach_master_signing_key(mut self) -> (Option<P384KeyPair>, Self) {
        match &mut self {
            Self {
                public: identity::Identity::X25519 { .. },
                secret: SecretKeys::X25519 { .. },
            } => (None, self),
            Self {
                public: identity::Identity::X25519P384 { .. },
                secret: SecretKeys::X25519P384 { master_signing_key, .. },
            }
            | Self {
                public: identity::Identity::P384 { .. },
                secret: SecretKeys::P384 { master_signing_key, .. },
            } => (master_signing_key.take(), self),
            _ => panic!("IdentitySecret in invalid state (public/secret type mismatch)"),
        }
    }

    /// Re-attach a master signing key secret to this identity secret.
    /// This will return an error if the supplied key does not match the public key in the public
    /// identity or of this is a legacy identity that doesn't support master signing keys.
    pub fn attach_master_signing_key(mut self, secret: P384KeyPair) -> Result<Self, InvalidParameterError> {
        match &mut self {
            Self {
                public: identity::Identity::X25519 { .. },
                secret: SecretKeys::X25519 { .. },
            } => Err(InvalidParameterError("legacy x25519 identities do not have master signing keys")),
            Self {
                public: identity::Identity::X25519P384 { master_signing_key, .. },
                secret: SecretKeys::X25519P384 { master_signing_key: master_signing_key_secret, .. },
            }
            | Self {
                public: identity::Identity::P384 { master_signing_key, .. },
                secret: SecretKeys::P384 { master_signing_key: master_signing_key_secret, .. },
            } => {
                if secret.public_key_bytes().eq(master_signing_key.as_bytes()) {
                    let _ = master_signing_key_secret.insert(secret);
                    Ok(self)
                } else {
                    Err(InvalidParameterError("master signing key secret does not match public"))
                }
            }
            _ => panic!("IdentitySecret in invalid state (public/secret type mismatch)"),
        }
    }
}

impl ToString for IdentitySecret {
    fn to_string(&self) -> String {
        match self {
            Self {
                public,
                secret: SecretKeys::X25519 { x25519_ecdh, x25519_eddsa },
            } => {
                // Type 0 identities convert to string form using the classical format.
                let mut s = public.to_string();
                s.push(':');
                s.push_str(hex::to_string(x25519_ecdh.secret_bytes().as_bytes()).as_str());
                s.push_str(hex::to_string(x25519_eddsa.secret_bytes().as_bytes()).as_str());
                s
            }
            _ => {
                // Other types just serialize as base64.
                let mut s = String::with_capacity(1024);
                s.push_str(self.public.address().to_string().as_str());
                s.push_str(":SECRET-");
                s.push_str(self.public.type_name());
                s.push(':');
                s.push_str(base64::to_string(self.to_bytes_on_stack::<32768>().as_bytes()).as_str());
                s
            }
        }
    }
}

impl FromStr for IdentitySecret {
    type Err = InvalidParameterError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut fi = s.trim().split(':');
        let _ = fi.next().ok_or(InvalidParameterError("incomplete"))?;
        let type_str = fi.next().ok_or(InvalidParameterError("incomplete"))?;
        let data_str = fi.next().ok_or(InvalidParameterError("incomplete"))?;

        if type_str == "0" {
            let secret_data = hex::from_string(fi.next().ok_or(InvalidParameterError("incomplete"))?);
            if secret_data.len() == (C25519_SECRET_KEY_SIZE + ED25519_SECRET_KEY_SIZE) {
                let public_id = Identity::from_str(s)?;
                if !matches!(&public_id, Identity::X25519 { .. }) {
                    return Err(InvalidParameterError("invalid type 0 identity"));
                }
                let x25519_public = public_id.x25519().unwrap();
                let x25519_ecdh = X25519KeyPair::from_bytes(x25519_public.0, &secret_data.as_slice()[..C25519_SECRET_KEY_SIZE])
                    .ok_or(InvalidParameterError("invalid key"))?;
                let x25519_eddsa = Ed25519KeyPair::from_bytes(x25519_public.1, &secret_data.as_slice()[C25519_SECRET_KEY_SIZE..])
                    .ok_or(InvalidParameterError("invalid key"))?;
                return Ok(Self {
                    public: public_id,
                    secret: SecretKeys::X25519 { x25519_ecdh, x25519_eddsa },
                });
            } else {
                return Err(InvalidParameterError("invalid key"));
            }
        } else if type_str.starts_with("SECRET") {
            let id = Self::from_bytes(
                base64::from_string(data_str.trim().as_bytes())
                    .ok_or(InvalidParameterError("invalid base64"))?
                    .as_slice(),
            )
            .map_err(|e| {
                println!("ERR: {}", e.to_string());
                InvalidParameterError("invalid identity")
            })?;
            return Ok(id);
        } else {
            return Err(InvalidParameterError("unrecognized type"));
        }
    }
}

impl ToFromBytes for IdentitySecret {
    fn read_bytes<R: std::io::Read>(r: &mut R) -> std::io::Result<Self> {
        let mut tmp = [0u8; 256];
        let public = Identity::read_bytes(r)?;
        let secret = match &public {
            Identity::X25519 { x25519_ecdh, x25519_eddsa, .. } => {
                const F0: usize = C25519_SECRET_KEY_SIZE;
                const F1: usize = F0 + ED25519_SECRET_KEY_SIZE;
                r.read_exact(&mut tmp[..F1])?;
                SecretKeys::X25519 {
                    x25519_ecdh: X25519KeyPair::from_bytes(x25519_ecdh, &tmp[..F0])
                        .ok_or(std::io::Error::new(std::io::ErrorKind::Other, "invalid key"))?,
                    x25519_eddsa: Ed25519KeyPair::from_bytes(x25519_eddsa, &tmp[F0..F1])
                        .ok_or(std::io::Error::new(std::io::ErrorKind::Other, "invalid key"))?,
                }
            }
            Identity::X25519P384 {
                master_signing_key,
                x25519_ecdh,
                x25519_eddsa,
                p384_ecdh,
                p384_ecdsa,
                ..
            } => {
                const F0: usize = 1 + P384_SECRET_KEY_SIZE;
                const F1: usize = F0 + C25519_SECRET_KEY_SIZE;
                const F2: usize = F1 + ED25519_SECRET_KEY_SIZE;
                const F3: usize = F2 + P384_SECRET_KEY_SIZE;
                const F4: usize = F3 + P384_SECRET_KEY_SIZE;
                r.read_exact(&mut tmp[..F4])?;
                SecretKeys::X25519P384 {
                    master_signing_key: if tmp[0] == (P384_SECRET_KEY_SIZE as u8) {
                        Some(
                            P384KeyPair::from_bytes(master_signing_key.as_bytes(), &tmp[1..F0])
                                .ok_or(std::io::Error::new(std::io::ErrorKind::Other, "invalid key"))?,
                        )
                    } else {
                        None
                    },
                    x25519_ecdh: X25519KeyPair::from_bytes(x25519_ecdh, &tmp[F0..F1])
                        .ok_or(std::io::Error::new(std::io::ErrorKind::Other, "invalid key"))?,
                    x25519_eddsa: Ed25519KeyPair::from_bytes(x25519_eddsa, &tmp[F1..F2])
                        .ok_or(std::io::Error::new(std::io::ErrorKind::Other, "invalid key"))?,
                    p384_ecdh: P384KeyPair::from_bytes(p384_ecdh.as_bytes(), &tmp[F2..F3])
                        .ok_or(std::io::Error::new(std::io::ErrorKind::Other, "invalid key"))?,
                    p384_ecdsa: P384KeyPair::from_bytes(p384_ecdsa.as_bytes(), &tmp[F3..F4])
                        .ok_or(std::io::Error::new(std::io::ErrorKind::Other, "invalid key"))?,
                }
            }
            Identity::P384 { master_signing_key, p384_ecdh, p384_ecdsa, .. } => {
                const F0: usize = 1 + P384_SECRET_KEY_SIZE;
                const F1: usize = F0 + P384_SECRET_KEY_SIZE;
                const F2: usize = F1 + P384_SECRET_KEY_SIZE;
                r.read_exact(&mut tmp[..F2])?;
                SecretKeys::P384 {
                    master_signing_key: if tmp[0] == P384_SECRET_KEY_SIZE as u8 {
                        Some(
                            P384KeyPair::from_bytes(master_signing_key.as_bytes(), &tmp[1..F0])
                                .ok_or(std::io::Error::new(std::io::ErrorKind::Other, "invalid key"))?,
                        )
                    } else {
                        None
                    },
                    p384_ecdh: P384KeyPair::from_bytes(p384_ecdh.as_bytes(), &tmp[F0..F1])
                        .ok_or(std::io::Error::new(std::io::ErrorKind::Other, "invalid key"))?,
                    p384_ecdsa: P384KeyPair::from_bytes(p384_ecdsa.as_bytes(), &tmp[F1..F2])
                        .ok_or(std::io::Error::new(std::io::ErrorKind::Other, "invalid key"))?,
                }
            }
        };
        return Ok(IdentitySecret { public, secret });
    }

    fn write_bytes<W: Write>(&self, w: &mut W) -> std::io::Result<()> {
        match self {
            IdentitySecret {
                public,
                secret:
                    SecretKeys::X25519 {
                        x25519_ecdh: x25519_ecdh_secret,
                        x25519_eddsa: x25519_eddsa_secret,
                    },
            } => {
                public.write_bytes(w)?;
                w.write_all(x25519_ecdh_secret.secret_bytes().as_bytes())?;
                w.write_all(x25519_eddsa_secret.secret_bytes().as_bytes())?;
            }
            IdentitySecret {
                public,
                secret:
                    SecretKeys::X25519P384 {
                        master_signing_key: master_signing_key_secret,
                        x25519_ecdh: x25519_ecdh_secret,
                        x25519_eddsa: x25519_eddsa_secret,
                        p384_ecdh: p384_ecdh_secret,
                        p384_ecdsa: p384_ecdsa_secret,
                    },
            } => {
                public.write_bytes(w)?;
                if let Some(master_signing_key_secret) = master_signing_key_secret.as_ref() {
                    w.write_all(&[P384_SECRET_KEY_SIZE as u8])?;
                    w.write_all(master_signing_key_secret.secret_key_bytes().as_bytes())?;
                } else {
                    w.write_all(&[0])?;
                }
                w.write_all(x25519_ecdh_secret.secret_bytes().as_bytes())?;
                w.write_all(x25519_eddsa_secret.secret_bytes().as_bytes())?;
                w.write_all(p384_ecdh_secret.secret_key_bytes().as_bytes())?;
                w.write_all(p384_ecdsa_secret.secret_key_bytes().as_bytes())?;
            }
            IdentitySecret {
                public,
                secret:
                    SecretKeys::P384 {
                        master_signing_key: master_signing_key_secret,
                        p384_ecdh: p384_ecdh_secret,
                        p384_ecdsa: p384_ecdsa_secret,
                    },
            } => {
                public.write_bytes(w)?;
                if let Some(master_signing_key_secret) = master_signing_key_secret.as_ref() {
                    w.write_all(&[P384_SECRET_KEY_SIZE as u8])?;
                    w.write_all(master_signing_key_secret.secret_key_bytes().as_bytes())?;
                } else {
                    w.write_all(&[0])?;
                }
                w.write_all(p384_ecdh_secret.secret_key_bytes().as_bytes())?;
                w.write_all(p384_ecdsa_secret.secret_key_bytes().as_bytes())?;
            }
        }
        Ok(())
    }
}

impl Serialize for IdentitySecret {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            self.to_string().serialize(serializer)
        } else {
            serializer.serialize_bytes(self.to_bytes_on_stack::<32768>().as_bytes())
        }
    }
}

struct IdentitySecretDeserializeVisitor;

impl<'de> serde::de::Visitor<'de> for IdentitySecretDeserializeVisitor {
    type Value = IdentitySecret;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("IdentitySecret")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        IdentitySecret::from_bytes(v).map_err(|e| serde::de::Error::custom(e.to_string()))
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        IdentitySecret::from_str(v).map_err(|e| serde::de::Error::custom(e.to_string()))
    }
}

impl<'de> Deserialize<'de> for IdentitySecret {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            deserializer.deserialize_str(IdentitySecretDeserializeVisitor)
        } else {
            deserializer.deserialize_bytes(IdentitySecretDeserializeVisitor)
        }
    }
}
