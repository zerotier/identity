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
use std::mem::transmute_copy;
use std::ptr::copy_nonoverlapping;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::zeroize::{Zeroize, ZeroizeOnDrop};
use zerotier_common_utils::blob::Blob;
use zerotier_common_utils::error::InvalidParameterError;
use zerotier_common_utils::hex;
use zerotier_common_utils::tofrombytes::ToFromBytes;
use zerotier_crypto_glue::hash::SHA512;
use zerotier_crypto_glue::salsa::Salsa;
use zerotier_crypto_glue::x25519::*;

use crate::{ADDRESS_ERR, IDENTITY_ERR};

/// Legacy 40-bit ZeroTier address.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Address([u8; 5]);

impl Address {
    pub const RESERVED_PREFIX: u8 = 0xff;

    fn is_valid(&self) -> bool {
        self.0[0] != Self::RESERVED_PREFIX && self.0.iter().any(|x| *x != 0)
    }
}

impl TryFrom<u64> for Address {
    type Error = InvalidParameterError;

    #[inline]
    fn try_from(value: u64) -> Result<Self, Self::Error> {
        let a = Self(value.to_be_bytes()[3..8].try_into().unwrap());
        if a.is_valid() {
            Ok(a)
        } else {
            Err(ADDRESS_ERR)
        }
    }
}

impl TryFrom<[u8; 5]> for Address {
    type Error = InvalidParameterError;

    #[inline]
    fn try_from(value: [u8; 5]) -> Result<Self, Self::Error> {
        let a = Self(value.try_into().unwrap());
        if a.is_valid() {
            Ok(a)
        } else {
            Err(ADDRESS_ERR)
        }
    }
}

impl ToString for Address {
    #[inline(always)]
    fn to_string(&self) -> String {
        hex::to_string(&self.0)
    }
}

impl Debug for Address {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.to_string().as_str())
    }
}

impl FromStr for Address {
    type Err = InvalidParameterError;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() == 10 {
            Self::try_from(hex::from_string_u64(s))
        } else {
            Err(InvalidParameterError(ADDRESS_ERR.0))
        }
    }
}

impl ToFromBytes for Address {
    #[inline(always)]
    fn read_bytes<R: std::io::Read>(r: &mut R) -> std::io::Result<Self> {
        let mut tmp = Self([0u8; 5]);
        r.read_exact(&mut tmp.0)?;
        if tmp.is_valid() {
            Ok(tmp)
        } else {
            Err(std::io::Error::new(std::io::ErrorKind::Other, ADDRESS_ERR.0))
        }
    }

    #[inline(always)]
    fn write_bytes<W: std::io::Write>(&self, w: &mut W) -> std::io::Result<()> {
        w.write_all(&self.0)
    }
}

impl AsRef<[u8]> for Address {
    #[inline(always)]
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Serialize for Address {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            self.to_string().serialize(serializer)
        } else {
            (self.0[0], self.0[1], self.0[2], self.0[3], self.0[4]).serialize(serializer)
        }
    }
}

impl<'de> Deserialize<'de> for Address {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            Address::from_str(<&str>::deserialize(deserializer)?).map_err(|_| serde::de::Error::custom(ADDRESS_ERR.0))
        } else {
            let b = <(u8, u8, u8, u8, u8)>::deserialize(deserializer)?;
            let a = Self([b.0, b.1, b.2, b.3, b.4]);
            if a.is_valid() {
                Ok(a)
            } else {
                Err(serde::de::Error::custom(ADDRESS_ERR.0))
            }
        }
    }
}

impl crate::Address for Address {
    const SIZE: usize = 5;
}

/// Legacy V1 ZeroTier identity based on x25519 elliptic curves.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Identity {
    pub address: Address,
    pub ecdh: [u8; C25519_PUBLIC_KEY_SIZE],
    pub eddsa: [u8; ED25519_PUBLIC_KEY_SIZE],
}

impl Identity {
    fn locally_validate(&self) -> bool {
        if self.address.is_valid() {
            let mut legacy_address_hasher = SHA512::new();
            legacy_address_hasher.update(&self.ecdh);
            legacy_address_hasher.update(&self.eddsa);
            let mut legacy_address_hash = legacy_address_hasher.finish();
            legacy_address_derivation_work_function(&mut legacy_address_hash);
            legacy_address_hash[0] < LEGACY_ADDRESS_POW_THRESHOLD && legacy_address_hash[59..64].eq(&self.address.0)
        } else {
            false
        }
    }
}

impl ToString for Identity {
    fn to_string(&self) -> String {
        let mut tmp = String::with_capacity(150);
        tmp.push_str(self.address.to_string().as_str());
        tmp.push_str(":0:");
        tmp.push_str(hex::to_string(&self.ecdh).as_str());
        tmp.push_str(hex::to_string(&self.eddsa).as_str());
        tmp
    }
}

impl Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("x25519::Identity")
            .field("address", &self.address)
            .field("ecdh", &self.ecdh)
            .field("eddsa", &self.eddsa)
            .finish()
    }
}

impl FromStr for Identity {
    type Err = InvalidParameterError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut s = s.split(':');
        let address = Address::from_str(s.next().ok_or(IDENTITY_ERR)?)?;
        if !s.next().map_or(false, |f| f == "0") {
            return Err(IDENTITY_ERR);
        }
        let bytes = hex::from_string(s.next().unwrap_or(""));
        if bytes.len() != C25519_PUBLIC_KEY_SIZE + ED25519_PUBLIC_KEY_SIZE {
            return Err(IDENTITY_ERR);
        }
        let id = Self {
            address,
            ecdh: bytes.as_slice()[..C25519_PUBLIC_KEY_SIZE].try_into().unwrap(),
            eddsa: bytes.as_slice()[C25519_PUBLIC_KEY_SIZE..].try_into().unwrap(),
        };
        if id.locally_validate() {
            return Ok(id);
        } else {
            return Err(IDENTITY_ERR);
        }
    }
}

impl ToFromBytes for Identity {
    fn read_bytes<R: std::io::Read>(r: &mut R) -> std::io::Result<Self> {
        let e = || Err(std::io::Error::new(std::io::ErrorKind::Other, IDENTITY_ERR.0))?;
        let mut tmp = [0u8; 5 + 1 + C25519_PUBLIC_KEY_SIZE + ED25519_PUBLIC_KEY_SIZE + 1];
        r.read_exact(&mut tmp)?;
        if tmp[5] != 0 {
            return e();
        }
        let id = Self {
            address: {
                let a = Address(tmp[..5].try_into().unwrap());
                if a.is_valid() {
                    a
                } else {
                    return e();
                }
            },
            ecdh: tmp[5 + 1..C25519_PUBLIC_KEY_SIZE + 6].try_into().unwrap(),
            eddsa: tmp[5 + 1 + C25519_PUBLIC_KEY_SIZE..5 + 1 + C25519_PUBLIC_KEY_SIZE + ED25519_PUBLIC_KEY_SIZE]
                .try_into()
                .unwrap(),
        };
        if id.locally_validate() {
            return Ok(id);
        } else {
            return e();
        }
    }

    fn write_bytes<W: std::io::Write>(&self, w: &mut W) -> std::io::Result<()> {
        w.write_all(&self.address.0)?;
        w.write_all(&[0])?;
        w.write_all(&self.ecdh)?;
        w.write_all(&self.eddsa)?;
        w.write_all(&[0])
    }
}

impl Hash for Identity {
    #[inline(always)]
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.address.hash(state);
    }
}

impl crate::Identity for Identity {
    const SIZE: usize = 5 + 1 + C25519_PUBLIC_KEY_SIZE + ED25519_PUBLIC_KEY_SIZE + 1;
    const SIGNATURE_SIZE: usize = 96;

    type Secret = IdentitySecret;

    #[inline(always)]
    fn verify_signature(&self, data: &[u8], signature: &[u8]) -> bool {
        ed25519_verify(&self.eddsa, signature, data)
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

impl<'de> Deserialize<'de> for Identity {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            Identity::from_str(<&str>::deserialize(deserializer)?).map_err(|_| serde::de::Error::custom(IDENTITY_ERR.0))
        } else {
            Identity::from_bytes(<&[u8]>::deserialize(deserializer)?)
                .map_err(|_| serde::de::Error::custom(IDENTITY_ERR.0))
        }
    }
}

/// Legacy V1 secret identity.
#[derive(Clone)]
pub struct IdentitySecret {
    pub public: Identity,
    pub ecdh: X25519KeyPair,
    pub eddsa: Ed25519KeyPair,
}

impl ToString for IdentitySecret {
    fn to_string(&self) -> String {
        let mut tmp = String::with_capacity(280);
        tmp.push_str(self.public.address.to_string().as_str());
        tmp.push_str(":0:");
        tmp.push_str(hex::to_string(&self.public.ecdh).as_str());
        tmp.push_str(hex::to_string(&self.public.eddsa).as_str());
        tmp.push(':');
        let mut buf = [0u8; ED25519_SECRET_KEY_SIZE];
        self.ecdh.secret_bytes(&mut buf);
        tmp.push_str(hex::to_string(&buf).as_str());
        self.eddsa.secret_bytes(&mut buf);
        tmp.push_str(hex::to_string(&buf).as_str());
        tmp
    }
}

impl FromStr for IdentitySecret {
    type Err = InvalidParameterError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let public = Identity::from_str(s)?;
        let s: Vec<&str> = s.split(':').collect();
        if s.len() != 4 {
            return Err(IDENTITY_ERR);
        }
        let secret_bytes = hex::from_string(s.get(3).unwrap());
        if secret_bytes.len() != C25519_SECRET_KEY_SIZE + ED25519_SECRET_KEY_SIZE {
            return Err(IDENTITY_ERR);
        }
        let ecdh = X25519KeyPair::from_bytes(
            &public.ecdh,
            &secret_bytes.as_slice()[..C25519_SECRET_KEY_SIZE].try_into().unwrap(),
        )
        .ok_or(IDENTITY_ERR)?;
        let eddsa = Ed25519KeyPair::from_bytes(
            &public.eddsa,
            &secret_bytes.as_slice()[C25519_SECRET_KEY_SIZE..].try_into().unwrap(),
        )
        .ok_or(IDENTITY_ERR)?;
        return Ok(Self { public, ecdh, eddsa });
    }
}

impl PartialEq for IdentitySecret {
    #[inline(always)]
    fn eq(&self, other: &Self) -> bool {
        self.public == other.public
    }
}

impl Eq for IdentitySecret {}

impl crate::IdentitySecret for IdentitySecret {
    type Public = Identity;
    type Signature = [u8; 96];

    fn generate(_timestamp: u64) -> Self {
        let mut ecdh = X25519KeyPair::generate();
        let eddsa = Ed25519KeyPair::generate();
        let mut legacy_address_hasher = SHA512::new();
        loop {
            legacy_address_hasher.update(&ecdh.public_bytes());
            legacy_address_hasher.update(&eddsa.public_bytes());
            let mut legacy_address_hash = legacy_address_hasher.finish();
            legacy_address_derivation_work_function(&mut legacy_address_hash);
            if legacy_address_hash[0] < LEGACY_ADDRESS_POW_THRESHOLD
                && legacy_address_hash[59] != Address::RESERVED_PREFIX
                && legacy_address_hash[59..64].iter().any(|i| *i != 0)
            {
                return Self {
                    public: Identity {
                        address: Address(legacy_address_hash[59..64].try_into().unwrap()),
                        ecdh: ecdh.public_bytes(),
                        eddsa: eddsa.public_bytes(),
                    },
                    ecdh,
                    eddsa,
                };
            } else {
                ecdh = X25519KeyPair::generate();
                legacy_address_hasher.reset();
            }
        }
    }

    #[inline(always)]
    fn public(&self) -> &Self::Public {
        &self.public
    }

    #[inline(always)]
    fn sign(&self, data: &[u8]) -> Self::Signature {
        self.eddsa.sign_zt(data)
    }
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct IdentitySecretSerialized {
    #[zeroize(skip)]
    a: Address,
    #[zeroize(skip)]
    p0: Blob<C25519_PUBLIC_KEY_SIZE>,
    s0: Blob<C25519_SECRET_KEY_SIZE>,
    #[zeroize(skip)]
    p1: Blob<ED25519_PUBLIC_KEY_SIZE>,
    s1: Blob<ED25519_SECRET_KEY_SIZE>,
}

impl Serialize for IdentitySecret {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut tmp = IdentitySecretSerialized {
            a: self.public.address,
            p0: self.public.ecdh.into(),
            s0: Blob::default(),
            p1: self.public.eddsa.into(),
            s1: Blob::default(),
        };
        self.ecdh.secret_bytes(&mut tmp.s0);
        self.eddsa.secret_bytes(&mut tmp.s1);
        tmp.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for IdentitySecret {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let d = <IdentitySecretSerialized>::deserialize(deserializer)?;
        if let (Some(ecdh), Some(eddsa)) = (
            X25519KeyPair::from_bytes(d.p0.as_bytes(), d.s0.as_bytes()),
            Ed25519KeyPair::from_bytes(d.p1.as_bytes(), d.s1.as_bytes()),
        ) {
            let id = Self {
                public: Identity {
                    address: d.a,
                    ecdh: ecdh.public_bytes(),
                    eddsa: eddsa.public_bytes(),
                },
                ecdh,
                eddsa,
            };
            if id.public.locally_validate() {
                return Ok(id);
            }
        }
        return Err(serde::de::Error::custom(IDENTITY_ERR.0));
    }
}

impl ToFromBytes for IdentitySecret {
    fn read_bytes<R: std::io::Read>(r: &mut R) -> std::io::Result<Self> {
        serde_cbor::from_reader(r).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
    }

    fn write_bytes<W: std::io::Write>(&self, w: &mut W) -> std::io::Result<()> {
        serde_cbor::to_writer(w, self).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
    }
}

/// First byte of a the legacy address derivation hash must be less than this.
const LEGACY_ADDRESS_POW_THRESHOLD: u8 = 17;

/// Memory-intensive hash used for address derivation in ZeroTier v1
fn legacy_address_derivation_work_function(digest_bytes: &mut [u8; 64]) {
    const ADDRESS_DERIVATION_HASH_MEMORY_SIZE: usize = 2097152;
    const ADDRESS_DERIVATION_HASH_MEMORY_SIZE_U64: usize = 2097152 / 8;

    let mut genmem: Box<[u64; ADDRESS_DERIVATION_HASH_MEMORY_SIZE_U64]> =
        unsafe { Box::from_raw(alloc(Layout::new::<[u64; ADDRESS_DERIVATION_HASH_MEMORY_SIZE_U64]>()).cast()) };

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

    unsafe { copy_nonoverlapping(digest.as_ptr().cast::<u8>(), digest_bytes.as_mut_ptr(), 64) };
}

#[cfg(test)]
mod tests {
    use crate::*;
    use zerotier_common_utils::ms_monotonic;

    #[test]
    fn generate() {
        let start = ms_monotonic();
        for _ in 0..3 {
            let secret = x25519::IdentitySecret::generate(0);
            println!("S: {}", secret.to_string());
            println!("P: {}", secret.public.to_string());
        }
        let end = ms_monotonic();
        println!("x25519 generation time: {} ms/identity", ((end - start) as f64) / 3.0);
    }

    #[test]
    fn tostring_fromstring() {
        let secret = x25519::IdentitySecret::generate(0);
        assert!(x25519::Address::from_str(secret.public.address.to_string().as_str())
            .unwrap()
            .eq(&secret.public.address));
        assert!(x25519::Identity::from_str(secret.public.to_string().as_str())
            .unwrap()
            .eq(&secret.public));
        assert!(x25519::IdentitySecret::from_str(secret.to_string().as_str())
            .unwrap()
            .eq(&secret));
    }

    #[test]
    fn tobytes_frombytes() {
        let secret = x25519::IdentitySecret::generate(0);
        assert!(x25519::Address::from_bytes(secret.public.address.to_bytes().as_slice())
            .unwrap()
            .eq(&secret.public.address));
        assert!(x25519::Identity::from_bytes(secret.public.to_bytes().as_slice())
            .unwrap()
            .eq(&secret.public));
        assert!(x25519::IdentitySecret::from_bytes(secret.to_bytes().as_slice())
            .unwrap()
            .eq(&secret));
    }

    #[test]
    fn known_good() {
        const KNOWN_GOOD: [&str; 4] = [
            "491287db97:0:00f7254a5e88878cc92e41d5be9533b3d52774a22a937ce4a2d2ff24915be138b3d6494264f5f208ccef162f27a3a7879472b141f3167975f4d0fc17b94d765f:4dfc009c3ee6103147f302fb71f1a3b11add9dd7c6ae4651976cffd8d1b2bf6bd11d0d50bcc5713524184323c29ffd4cd3009897b06b4c0f743a5e541de5479c",
            "2fd3e47197:0:b42f063109e84fc39d01fd14b923739b64193a403ff88281590f35a13a42c966ebb5f0b8044d140a39982bc951e7841de931442b2bb63a06801e565a4770b65b:0e844a9ccda42451ccef921527826e6dcb917f8f8dc95fc030624c1d40fc9b18e163d7a98c36ae27a45e00afeb043fa58f41c2f9ac64bd817ed6b49ff965ddc2",
            "f732a2db3a:0:6652843b5b0cc886be24b49f250b32b9d3057952cb801d818f492af7ef78f47fc32dc46fe7c3d3180c4bc5fce92635d7c07af3978ea10904f9bc219dfe154d0f:a2e24b9c6c537f37aae3f6c3caa117dec196ec58e48a8bb5be51c063e41ce645264d7c68e8c888ed1acc2f1a08586c9755625e264a0617e503334cc784afddcf",
            "bfa6e78018:0:04d6e19a1b5c9bad615b453e7ce30988949aff7dbaa9e4cf4afb315d1d5aca0642a67c79e4f16c55c1306109a44c203e6e04dc3229f4bc37098b2ce14fd2f8be:77b068d3bc02d7bbb25d9051faef46fa66745d121b619a1d789d93984dac27571a3be106d7bead9ca7b6eeec2c6e56a35b680b101e750136aa13da9147a2edad",
        ];
        for s in KNOWN_GOOD {
            let secret = x25519::IdentitySecret::from_str(s).unwrap();
            let sig = secret.sign(b"asdf");
            assert!(secret.public.verify_signature(b"asdf", &sig));
        }
    }

    #[test]
    fn known_bad() {
        const KNOWN_BAD: [&str; 4] = [
            "491287db97:0:00f7254f5e88878cc92e41d5be9533b3d52774a22a937ce4a2d2ff24915be138b3d6494264f5f208ccef162f27a3a7879472b141f3167975f4d0fc17b94d765f:4dfc009c3ee6103147f302fb71f1a3b11add9dd7c6ae4651976cffd8d1b2bf6bd11d0d50bcc5713524184323c29ffd4cd3009897b06b4c0f743a5e541de5479c",
            "2fd3e57197:0:b42f063109e84fc39d01fd14b923739b64193a403ff88281590f35a13a42c966ebb5f0b8044d140a39982bc951e7841de931442b2bb63a06801e565a4770b65b:0e844a9ccda42451ccef921527826e6dcb917f8f8dc95fc030624c1d40fc9b18e163d7a98c36ae27a45e00afeb043fa58f41c2f9ac64bd817ed6b49ff965ddc2",
            "f732a2db3a:1:6652843b5b0cc886be24b49f250b32b9d3057952cb801d818f492af7ef78f47fc32dc46fe7c3d3180c4bc5fce92635d7c07af3978ea10904f9bc219dfe154d0f:a2e24b9c6c537f37aae3f6c3caa117dec196ec58e48a8bb5be51c063e41ce645264d7c68e8c888ed1acc2f1a08586c9755625e264a0617e503334cc784afddcf",
            "0fa6e78018:0:04d6e19a1b5c9bad615b353e7ce30988949aff7dbaa9e4cf4afb315d1d5aca0642a67c79e4f16c55c1306109a44c203e6e04dc3229f4bc37098b2ce14fd2f8be:77b068d3bc02d7bbb25d9051faef46fa66745d121b619a1d789d93984dac27571a3be106d7bead9ca7b6eeec2c6e56a35b680b101e750136aa13da9147a2edad",
        ];
        for s in KNOWN_BAD {
            assert!(x25519::IdentitySecret::from_str(s).is_err());
        }
    }
}
