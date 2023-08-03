use std::alloc::{alloc, Layout};
use std::hash::Hash;
use std::mem::transmute_copy;
use std::ptr::copy_nonoverlapping;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use zerotier_common_utils::blob::Blob;
use zerotier_common_utils::error::InvalidParameterError;
use zerotier_common_utils::hex;
use zerotier_common_utils::tofrombytes::ToFromBytes;
use zerotier_crypto_glue::hash::SHA512;
use zerotier_crypto_glue::salsa::Salsa;
use zerotier_crypto_glue::x25519::*;

const ADDRESS_ERR: InvalidParameterError = InvalidParameterError("invalid address");
const IDENTITY_ERR: InvalidParameterError = InvalidParameterError("invalid identity");

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

impl FromStr for Address {
    type Err = InvalidParameterError;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() == 10 {
            Self::try_from(hex::from_string_u64(s))
        } else {
            Err(InvalidParameterError("invalid address"))
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
            Err(std::io::Error::new(std::io::ErrorKind::Other, "invalid address"))
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
            serializer.serialize_bytes(&self.0)
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
            Address::from_bytes(<&[u8]>::deserialize(deserializer)?).map_err(|_| serde::de::Error::custom(ADDRESS_ERR.0))
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
        let mut legacy_address_hasher = SHA512::new();
        legacy_address_hasher.update(&self.ecdh);
        legacy_address_hasher.update(&self.eddsa);
        let mut legacy_address_hash = legacy_address_hasher.finish();
        legacy_address_derivation_work_function(&mut legacy_address_hash);
        legacy_address_hash[0] < LEGACY_ADDRESS_POW_THRESHOLD && legacy_address_hash[59..64].eq(&self.address.0)
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
            Identity::from_bytes(<&[u8]>::deserialize(deserializer)?).map_err(|_| serde::de::Error::custom(IDENTITY_ERR.0))
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
        tmp.push_str(hex::to_string(self.ecdh.secret_bytes().as_bytes()).as_str());
        tmp.push_str(hex::to_string(self.eddsa.secret_bytes().as_bytes()).as_str());
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
        let ecdh = X25519KeyPair::from_bytes(&public.ecdh, &secret_bytes.as_slice()[..C25519_SECRET_KEY_SIZE]).ok_or(IDENTITY_ERR)?;
        let eddsa = Ed25519KeyPair::from_bytes(&public.eddsa, &secret_bytes.as_slice()[C25519_SECRET_KEY_SIZE..]).ok_or(IDENTITY_ERR)?;
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

impl PartialOrd for IdentitySecret {
    #[inline(always)]
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.public.partial_cmp(&other.public)
    }
}

impl Ord for IdentitySecret {
    #[inline(always)]
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.public.cmp(&other.public)
    }
}

impl Hash for IdentitySecret {
    #[inline(always)]
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.public.hash(state);
    }
}

impl crate::IdentitySecret for IdentitySecret {
    type Public = Identity;
    type Signature = [u8; 96];

    fn generate() -> Self {
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

#[derive(Serialize, Deserialize)]
struct IdentitySecretSerialized {
    a: Blob<5>,
    p0: Blob<C25519_PUBLIC_KEY_SIZE>,
    s0: Blob<C25519_SECRET_KEY_SIZE>,
    p1: Blob<ED25519_PUBLIC_KEY_SIZE>,
    s1: Blob<ED25519_SECRET_KEY_SIZE>,
}

impl Serialize for IdentitySecret {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        IdentitySecretSerialized {
            a: self.public.address.0.into(),
            p0: self.public.ecdh.into(),
            s0: (*self.ecdh.secret_bytes().as_bytes()).into(),
            p1: self.public.eddsa.into(),
            s1: (*self.eddsa.secret_bytes().as_bytes()).into(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for IdentitySecret {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let d = <IdentitySecretSerialized>::deserialize(deserializer)?;
        let ecdh = X25519KeyPair::from_bytes(d.p0.as_bytes(), d.s0.as_bytes());
        let eddsa = Ed25519KeyPair::from_bytes(d.p1.as_bytes(), d.s1.as_bytes());
        if ecdh.is_none() || eddsa.is_none() {
            return Err(serde::de::Error::custom(IDENTITY_ERR.0));
        }
        let ecdh = ecdh.unwrap();
        let eddsa = eddsa.unwrap();
        let id = Self {
            public: Identity {
                address: Address(d.a.into()),
                ecdh: ecdh.public_bytes(),
                eddsa: eddsa.public_bytes(),
            },
            ecdh,
            eddsa,
        };
        if !id.public.address.is_valid() || !id.public.locally_validate() {
            return Err(serde::de::Error::custom(IDENTITY_ERR.0));
        }
        return Ok(id);
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
            let secret = x25519::IdentitySecret::generate();
            println!("S: {}", secret.to_string());
            println!("P: {}", secret.public.to_string());
        }
        let end = ms_monotonic();
        println!("generation time: {} ms/identity", ((end - start) as f64) / 3.0);
    }

    #[test]
    fn tostring_fromstring() {
        let secret = x25519::IdentitySecret::generate();
        assert!(x25519::Address::from_str(secret.public.address.to_string().as_str())
            .unwrap()
            .eq(&secret.public.address));
        assert!(x25519::Identity::from_str(secret.public.to_string().as_str()).unwrap().eq(&secret.public));
        assert!(x25519::IdentitySecret::from_str(secret.to_string().as_str()).unwrap().eq(&secret));
    }

    #[test]
    fn tobytes_frombytes() {
        let secret = x25519::IdentitySecret::generate();
        assert!(x25519::Address::from_bytes(secret.public.address.to_bytes().as_slice())
            .unwrap()
            .eq(&secret.public.address));
        assert!(x25519::Identity::from_bytes(secret.public.to_bytes().as_slice())
            .unwrap()
            .eq(&secret.public));
        assert!(x25519::IdentitySecret::from_bytes(secret.to_bytes().as_slice()).unwrap().eq(&secret));
    }
}
