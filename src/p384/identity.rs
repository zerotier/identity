/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * (c) ZeroTier, Inc.
 * https://www.zerotier.com/
 */
use crate::p384::*;

const MASTER_KEY_START: usize = 1;
const TIMESTAMP_START: usize = MASTER_KEY_START + P384_PUBLIC_KEY_SIZE;
const SUBKEY_ECDH_START: usize = TIMESTAMP_START + 8;
const SUBKEY_ECDSA_START: usize = SUBKEY_ECDH_START + P384_PUBLIC_KEY_SIZE;
const MASTER_SIG_START: usize = SUBKEY_ECDSA_START + P384_PUBLIC_KEY_SIZE;
const SUBKEY_SIG_START: usize = MASTER_SIG_START + P384_ECDSA_SIGNATURE_SIZE;
const P384_IDENTITY_SIZE: usize = SUBKEY_SIG_START + P384_ECDSA_SIGNATURE_SIZE;

/// NIST P-384 based new format identity with key upgrade capability.
#[derive(Clone)]
pub struct Identity {
    pub address: Address,
    pub master_signing_key: P384PublicKey,
    pub timestamp: u64,
    pub ecdh: P384PublicKey,
    pub ecdsa: P384PublicKey,
    pub master_signature: [u8; P384_ECDSA_SIGNATURE_SIZE],
    pub ecdsa_signature: [u8; P384_ECDSA_SIGNATURE_SIZE],
}

impl Identity {
    pub const SIZE: usize = P384_IDENTITY_SIZE;

    pub const STRING_SIZE: usize = 548;
    pub const STRING_SIZE_NO_PREFIX: usize = 543;

    pub fn prefix(&self) -> &ShortAddress {
        self.address.prefix()
    }

    pub(crate) fn locally_validate(&self) -> bool {
        let to_sign: &[&[u8]] = &[
            self.master_signing_key.as_bytes(),
            &self.timestamp.to_be_bytes(),
            self.ecdh.as_bytes(),
            self.ecdsa.as_bytes(),
        ];

        self.address.is_valid()
            && self
                .master_signing_key
                .verify_all(DOMAIN_MASTER_SIG, to_sign, &self.master_signature)
            && self.ecdsa.verify_all(DOMAIN_SUBKEY_SIG, to_sign, &self.ecdsa_signature)
    }

    /// Returns true if this identity should replace the other.
    /// This just returns true if the timestamp is newer and the address (master signing key hash) is the same.
    #[inline(always)]
    pub fn replaces(&self, other: &Identity) -> bool {
        self.address == other.address && self.timestamp > other.timestamp
    }

    pub fn write_to_string(&self, s: &mut String, prefix: bool) {
        if prefix {
            s.push_str(PREFIX_IDENTITY);
        }
        self.address.write_to_string(s, false);
        s.push_str(":1:");
        s.push_str(base64::to_string(self.to_bytes_on_stack::<1024>().as_bytes()).as_str());
    }
}

impl ToString for Identity {
    fn to_string(&self) -> String {
        let mut s = String::with_capacity(Self::STRING_SIZE);
        self.write_to_string(&mut s, true);
        s
    }
}

impl Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("x25519::Identity")
            .field("address", &self.address)
            .field("master_signing_key", self.master_signing_key.as_bytes())
            .field("timestamp", &self.timestamp)
            .field("ecdh", self.ecdh.as_bytes())
            .field("ecdsa", self.ecdsa.as_bytes())
            .field("master_signature", &self.master_signature)
            .field("ecdsa_signature", &self.ecdsa_signature)
            .finish()
    }
}

impl FromStr for Identity {
    type Err = InvalidParameterError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        let s = s.strip_prefix(PREFIX_IDENTITY).unwrap_or(s);
        if let Some(div_idx) = s.rfind(':') {
            if div_idx > 0 && div_idx < s.len() {
                if let Some(bytes) = base64::from_string(s[div_idx + 1..].as_bytes()) {
                    return Self::from_bytes(bytes.as_slice()).map_err(|_| IDENTITY_ERR);
                }
            }
        }
        Err(IDENTITY_ERR)
    }
}

impl ToFromBytes for Identity {
    fn read_bytes<R: std::io::Read>(r: &mut R) -> std::io::Result<Self> {
        let mut tmp = [0u8; P384_IDENTITY_SIZE];
        r.read_exact(&mut tmp)?;
        if let (Some(master_signing_key), Some(ecdh), Some(ecdsa)) = (
            P384PublicKey::from_bytes(&tmp[MASTER_KEY_START..TIMESTAMP_START]),
            P384PublicKey::from_bytes(&tmp[SUBKEY_ECDH_START..SUBKEY_ECDSA_START]),
            P384PublicKey::from_bytes(&tmp[SUBKEY_ECDSA_START..MASTER_SIG_START]),
        ) {
            let id = Self {
                address: Address(unsafe { transmute(SHA384::hash(master_signing_key.as_bytes())) }),
                master_signing_key,
                timestamp: u64::from_be_bytes(tmp[TIMESTAMP_START..SUBKEY_ECDH_START].try_into().unwrap()),
                ecdh,
                ecdsa,
                master_signature: tmp[MASTER_SIG_START..SUBKEY_SIG_START].try_into().unwrap(),
                ecdsa_signature: tmp[SUBKEY_SIG_START..P384_IDENTITY_SIZE].try_into().unwrap(),
            };
            if id.locally_validate() {
                return Ok(id);
            }
        }
        Err(std::io::Error::new(std::io::ErrorKind::Other, IDENTITY_ERR.0))
    }

    /// This function cannot rollback changes to `w` if an error occurs.
    fn write_bytes<W: std::io::Write>(&self, w: &mut W) -> std::io::Result<()> {
        // The address is SHA384(master_signing_key) so we do not need to output it. We will want
        // to recalculate it to check it anyway.
        w.write_all(&[IDENTITY_VARIANT_P384])?;
        w.write_all(self.master_signing_key.as_bytes())?;
        w.write_all(&self.timestamp.to_be_bytes())?;
        w.write_all(self.ecdh.as_bytes())?;
        w.write_all(self.ecdsa.as_bytes())?;
        w.write_all(&self.master_signature)?;
        w.write_all(&self.ecdsa_signature)
    }
}

impl Serialize for Identity {
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            self.to_string().serialize(serializer)
        } else {
            serializer.serialize_bytes(self.to_bytes_on_stack::<P384_IDENTITY_SIZE>().as_ref())
        }
    }
}

impl<'de> Deserialize<'de> for Identity {
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            Identity::from_str(<&str>::deserialize(deserializer)?).map_err(|_| serde::de::Error::custom(IDENTITY_ERR.0))
        } else {
            struct Visitor;

            impl<'de> serde::de::Visitor<'de> for Visitor {
                type Value = Identity;

                fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                    formatter.write_str("a zerotier identifier")
                }

                fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    Identity::from_bytes(v).map_err(|_| serde::de::Error::custom(IDENTITY_ERR.0))
                }
            }
            deserializer.deserialize_bytes(Visitor)
        }
    }
}

impl PartialEq for Identity {
    #[inline(always)]
    fn eq(&self, other: &Self) -> bool {
        // Two identities are equal if their addresses, which are SHA384(master signing key), match and
        // if their signatures match. The latter is because differing signatures would indicate different
        // revisions of the working keys within an identity.
        self.address.eq(&other.address) && self.master_signature.eq(&other.master_signature)
    }
}

impl Eq for Identity {}

impl PartialOrd for Identity {
    #[inline(always)]
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.address.cmp(&other.address))
    }
}

impl Ord for Identity {
    #[inline(always)]
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.address.cmp(&other.address)
    }
}

impl Hash for Identity {
    #[inline(always)]
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.address.hash(state);
    }
}

impl crate::Identity for Identity {
    const SIZE: usize = P384_IDENTITY_SIZE;
    const SIGNATURE_SIZE: usize = P384_ECDSA_SIGNATURE_SIZE;

    type Secret = IdentitySecret;

    #[inline(always)]
    fn verify_signature(&self, data: &[u8], signature: &[u8]) -> bool {
        if let Ok(sig) = signature.try_into() {
            self.ecdsa.verify_raw(data, sig)
        } else {
            false
        }
    }

    #[inline(always)]
    fn verify_domain_restricted_signature(&self, domain: &[u8], data: &[u8], signature: &[u8]) -> bool {
        if let Ok(sig) = signature.try_into() {
            self.ecdsa.verify(domain, data, sig)
        } else {
            false
        }
    }
}
