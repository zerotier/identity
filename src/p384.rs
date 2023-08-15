/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * (c) ZeroTier, Inc.
 * https://www.zerotier.com/
 */

use std::hash::Hash;
use std::io::Write;
use std::mem::{size_of, transmute};
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use zeroize::{Zeroize, ZeroizeOnDrop};
use zerotier_common_utils::base64;
use zerotier_common_utils::blob::Blob;
use zerotier_common_utils::error::InvalidParameterError;
use zerotier_common_utils::tofrombytes::ToFromBytes;
use zerotier_crypto_glue::hash::SHA384;
use zerotier_crypto_glue::p384::*;

use crate::{base24, base62};
use crate::{ADDRESS_ERR, IDENTITY_ERR};

const IDENTITY_DOMAIN: &[u8] = b"identity_subkeys_p384";

// Implementation note: the addresses use u64 arrays that are actually treated as flat byte
// array memory arenas in order to optimize for fast lookup when these are used as map keys.
// This reduces the number of instructions required to perform equality comparisons and
// simplifies the implementation of Hash. The effect is small but might matter at scale.

/// 384-bit ZeroTier address.
/// An address is the SHA384(public master signing key) of an identity.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Address([u64; 6]); // treated as [u8; 48]

/// 128-bit short address prefix.
///
/// Short addresses are primarily for cases where humans need to type addresses or where
/// they need to be mapped onto an IPv6 address. The fully qualified 384-bit address
/// should be preferred if address transfer is automated or via cut/paste.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ShortAddress([u64; 2]); // treated as [u8; 16]

impl Address {
    /// The first byte of a valid address must be 0xfc.
    ///
    /// This allows the 128-bit prefix of every address to also be a valid private IPv6 address,
    /// which is useful for a number of purposes. It also imposes a small extra computational cost
    /// on the generation of new identities with a given short address, making it slightly harder
    /// to brute force the short address space. (A 128-bit space is already impractical to brute
    /// force, but untargeted birthday type collisions are possible with sufficient storage.)
    pub const REQUIRED_PREFIX: u8 = 0xfc;

    /// Length of a full address in string format.
    pub const STRING_SIZE: usize = 76;

    /// Get this address as a raw byte array.
    #[inline(always)]
    pub fn as_bytes(&self) -> &[u8; 48] {
        debug_assert_eq!(size_of::<[u8; 48]>(), size_of::<Self>());
        unsafe { &*self.0.as_ptr().cast::<[u8; 48]>() }
    }

    /// Get this address's 128-bit short prefix.
    #[inline(always)]
    pub fn prefix(&self) -> &ShortAddress {
        unsafe { transmute(&self.0) }
    }

    /// Get mutable bytes.
    /// This is private because it should be impossible for external code to create an invalid address.
    #[inline(always)]
    fn as_mut_bytes(&mut self) -> &mut [u8; 48] {
        debug_assert_eq!(size_of::<[u8; 48]>(), size_of::<Self>());
        unsafe { &mut *self.0.as_mut_ptr().cast::<[u8; 48]>() }
    }

    /// Check address validity, used in deserialization code.
    #[inline(always)]
    fn is_valid(&self) -> bool {
        self.as_bytes()[0] == Self::REQUIRED_PREFIX
    }
}

impl ShortAddress {
    #[inline(always)]
    pub fn as_bytes(&self) -> &[u8; 16] {
        debug_assert_eq!(size_of::<[u8; 16]>(), size_of::<Self>());
        unsafe { &*(&self.0 as *const [u64; 2]).cast() }
    }

    #[inline(always)]
    fn as_mut_bytes(&mut self) -> &mut [u8; 16] {
        debug_assert_eq!(size_of::<[u8; 16]>(), size_of::<Self>());
        unsafe { &mut *(&mut self.0 as *mut [u64; 2]).cast() }
    }

    #[inline(always)]
    fn is_valid(&self) -> bool {
        self.as_bytes()[0] == Address::REQUIRED_PREFIX
    }
}

impl TryFrom<[u8; 48]> for Address {
    type Error = InvalidParameterError;

    #[inline]
    fn try_from(value: [u8; 48]) -> Result<Self, Self::Error> {
        let a = Self(unsafe { transmute(value) });
        if a.is_valid() {
            Ok(a)
        } else {
            Err(ADDRESS_ERR)
        }
    }
}

impl TryFrom<[u8; 16]> for ShortAddress {
    type Error = InvalidParameterError;

    #[inline]
    fn try_from(value: [u8; 16]) -> Result<Self, Self::Error> {
        let a = Self(unsafe { transmute(value) });
        if a.is_valid() {
            Ok(a)
        } else {
            Err(ADDRESS_ERR)
        }
    }
}

impl From<Address> for [u8; 48] {
    #[inline(always)]
    fn from(value: Address) -> Self {
        unsafe { transmute(value) }
    }
}

impl From<ShortAddress> for [u8; 16] {
    #[inline(always)]
    fn from(value: ShortAddress) -> Self {
        unsafe { transmute(value) }
    }
}

fn first_128_to_string(b: &[u8], s: &mut String) {
    base24::encode_4to7(&b[0..4], s);
    s.push('.');
    base24::encode_4to7(&b[4..8], s);
    s.push('.');
    base24::encode_4to7(&b[8..12], s);
    s.push('.');
    base24::encode_4to7(&b[12..16], s);
}

impl ToString for Address {
    fn to_string(&self) -> String {
        let mut s = String::with_capacity(Self::STRING_SIZE);
        first_128_to_string(&self.as_bytes()[..16], &mut s);
        s.push('.');
        base62::encode_8to11(u64::from_be(self.0[2]), &mut s);
        base62::encode_8to11(u64::from_be(self.0[3]), &mut s);
        base62::encode_8to11(u64::from_be(self.0[4]), &mut s);
        base62::encode_8to11(u64::from_be(self.0[5]), &mut s);
        s
    }
}

impl ToString for ShortAddress {
    fn to_string(&self) -> String {
        let mut s = String::with_capacity(32);
        first_128_to_string(self.as_bytes(), &mut s);
        s
    }
}

impl FromStr for Address {
    type Err = InvalidParameterError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        let sb = s.as_bytes();
        if s.len() == sb.len() && sb.len() == Self::STRING_SIZE && sb[31] == b'.' {
            let prefix = ShortAddress::from_str(&s[..31])?;
            Ok(Address([
                prefix.0[0],
                prefix.0[1],
                base62::decode_11to8(&sb[32..43])?.to_be(),
                base62::decode_11to8(&sb[43..54])?.to_be(),
                base62::decode_11to8(&sb[54..65])?.to_be(),
                base62::decode_11to8(&sb[65..76])?.to_be(),
            ]))
        } else {
            Err(ADDRESS_ERR)
        }
    }
}

impl FromStr for ShortAddress {
    type Err = InvalidParameterError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        if s.len() == 31 {
            let mut tmp = [0u8; 16];
            let mut w = &mut tmp[..];
            for ss in s.split('.') {
                if ss.len() == 7 {
                    let _ = w.write_all(&base24::decode_7to4(ss.as_bytes())?);
                } else {
                    return Err(ADDRESS_ERR);
                }
                if w.is_empty() {
                    return Self::try_from(tmp);
                }
            }
        }
        return Err(ADDRESS_ERR);
    }
}

impl ToFromBytes for Address {
    #[inline]
    fn read_bytes<R: std::io::Read>(r: &mut R) -> std::io::Result<Self> {
        let mut tmp = Self([0; 6]);
        r.read_exact(tmp.as_mut_bytes())?;
        if tmp.is_valid() {
            Ok(tmp)
        } else {
            Err(std::io::Error::new(std::io::ErrorKind::Other, ADDRESS_ERR.0))
        }
    }

    #[inline(always)]
    fn write_bytes<W: std::io::Write>(&self, w: &mut W) -> std::io::Result<()> {
        w.write_all(self.as_bytes())
    }
}

impl ToFromBytes for ShortAddress {
    #[inline]
    fn read_bytes<R: std::io::Read>(r: &mut R) -> std::io::Result<Self> {
        let mut tmp = Self([0; 2]);
        r.read_exact(tmp.as_mut_bytes())?;
        if tmp.is_valid() {
            Ok(tmp)
        } else {
            Err(std::io::Error::new(std::io::ErrorKind::Other, ADDRESS_ERR.0))
        }
    }

    #[inline(always)]
    fn write_bytes<W: std::io::Write>(&self, w: &mut W) -> std::io::Result<()> {
        w.write_all(self.as_bytes())
    }
}

impl AsRef<[u8]> for Address {
    #[inline(always)]
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl AsRef<[u8]> for ShortAddress {
    #[inline(always)]
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl Hash for Address {
    #[inline(always)]
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        state.write_usize(self.0[0] as usize)
    }
}

impl Hash for ShortAddress {
    #[inline(always)]
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        state.write_usize(self.0[0] as usize)
    }
}

impl PartialOrd for Address {
    #[inline(always)]
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialOrd for ShortAddress {
    #[inline(always)]
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Address {
    #[inline(always)]
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0
            .iter()
            .map(|i| u64::from_be(*i))
            .cmp(other.0.iter().map(|i| u64::from_be(*i)))
    }
}

impl Ord for ShortAddress {
    #[inline(always)]
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0
            .iter()
            .map(|i| u64::from_be(*i))
            .cmp(other.0.iter().map(|i| u64::from_be(*i)))
    }
}

impl Serialize for Address {
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            self.to_string().serialize(serializer)
        } else {
            <&Blob<48>>::from(self.as_bytes()).serialize(serializer)
        }
    }
}

impl<'de> Deserialize<'de> for Address {
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            Address::from_str(<&str>::deserialize(deserializer)?).map_err(|_| serde::de::Error::custom(ADDRESS_ERR.0))
        } else {
            Address::try_from(<[u8; 48]>::from(Blob::<48>::deserialize(deserializer)?))
                .map_err(|_| serde::de::Error::custom(ADDRESS_ERR.0))
        }
    }
}

impl Serialize for ShortAddress {
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            self.to_string().serialize(serializer)
        } else {
            <&Blob<16>>::from(self.as_bytes()).serialize(serializer)
        }
    }
}

impl<'de> Deserialize<'de> for ShortAddress {
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            ShortAddress::from_str(<&str>::deserialize(deserializer)?)
                .map_err(|_| serde::de::Error::custom(ADDRESS_ERR.0))
        } else {
            ShortAddress::try_from(<[u8; 16]>::from(Blob::<16>::deserialize(deserializer)?))
                .map_err(|_| serde::de::Error::custom(ADDRESS_ERR.0))
        }
    }
}

impl crate::Address for Address {
    const SIZE: usize = 48;
}

/// NIST P-384 based new format identity with key upgrade capability.
#[derive(Clone)]
pub struct Identity {
    pub address: Address,
    pub master_signing_key: P384PublicKey,
    pub timestamp: u64,
    pub ecdh: P384PublicKey,
    pub ecdsa: P384PublicKey,
    pub master_signature: [u8; P384_ECDSA_SIGNATURE_SIZE],
}

impl Identity {
    fn locally_validate(&self) -> bool {
        self.address.is_valid()
            && self.master_signing_key.verify_all(
                IDENTITY_DOMAIN,
                &[
                    &self.timestamp.to_be_bytes(),
                    self.ecdh.as_bytes(),
                    self.ecdsa.as_bytes(),
                ],
                &self.master_signature,
            )
    }

    /// Returns true if this identity should replace the other.
    /// This just returns true if the timestamp is newer and the address (master signing key hash) is the same.
    #[inline(always)]
    pub fn replaces(&self, other: &Identity) -> bool {
        self.address == other.address && self.timestamp > other.timestamp
    }
}

impl ToString for Identity {
    fn to_string(&self) -> String {
        let mut tmp = String::with_capacity(1024);
        tmp.push_str(self.address.to_string().as_str());
        tmp.push_str(":1:");
        tmp.push_str(base64::to_string(self.to_bytes_on_stack::<1024>().as_bytes()).as_str());
        tmp
    }
}

impl FromStr for Identity {
    type Err = InvalidParameterError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(div_idx) = s.rfind(':') {
            if div_idx > 0 && div_idx < s.len() {
                if let Some(bytes) = base64::from_string(s[div_idx + 1..].as_bytes()) {
                    return Self::from_bytes(bytes.as_slice()).map_err(|_| IDENTITY_ERR);
                }
            }
        }
        return Err(IDENTITY_ERR);
    }
}

impl ToFromBytes for Identity {
    fn read_bytes<R: std::io::Read>(r: &mut R) -> std::io::Result<Self> {
        let mut tmp =
            [0u8; P384_PUBLIC_KEY_SIZE + 8 + P384_PUBLIC_KEY_SIZE + P384_PUBLIC_KEY_SIZE + P384_ECDSA_SIGNATURE_SIZE];
        r.read_exact(&mut tmp)?;
        if let (Some(master_signing_key), Some(ecdh), Some(ecdsa)) = (
            P384PublicKey::from_bytes(&tmp[..P384_PUBLIC_KEY_SIZE]),
            P384PublicKey::from_bytes(&tmp[P384_PUBLIC_KEY_SIZE + 8..P384_PUBLIC_KEY_SIZE + 8 + P384_PUBLIC_KEY_SIZE]),
            P384PublicKey::from_bytes(
                &tmp[P384_PUBLIC_KEY_SIZE + 8 + P384_PUBLIC_KEY_SIZE
                    ..P384_PUBLIC_KEY_SIZE + 8 + P384_PUBLIC_KEY_SIZE + P384_PUBLIC_KEY_SIZE],
            ),
        ) {
            let id = Self {
                address: Address(unsafe { transmute(SHA384::hash(master_signing_key.as_bytes())) }),
                master_signing_key,
                timestamp: u64::from_be_bytes(tmp[P384_PUBLIC_KEY_SIZE..P384_PUBLIC_KEY_SIZE + 8].try_into().unwrap()),
                ecdh,
                ecdsa,
                master_signature: tmp[P384_PUBLIC_KEY_SIZE + 8 + P384_PUBLIC_KEY_SIZE + P384_PUBLIC_KEY_SIZE..]
                    .try_into()
                    .unwrap(),
            };
            if id.locally_validate() {
                return Ok(id);
            }
        }
        return Err(std::io::Error::new(std::io::ErrorKind::Other, IDENTITY_ERR.0));
    }

    fn write_bytes<W: std::io::Write>(&self, w: &mut W) -> std::io::Result<()> {
        // The address is SHA384(master_signing_key) so we do not need to output it. We will want
        // to recalculate it to check it anyway.
        w.write_all(self.master_signing_key.as_bytes())?;
        w.write_all(&self.timestamp.to_be_bytes())?;
        w.write_all(self.ecdh.as_bytes())?;
        w.write_all(self.ecdsa.as_bytes())?;
        w.write_all(&self.master_signature)
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
    const SIZE: usize =
        P384_PUBLIC_KEY_SIZE + 8 + P384_PUBLIC_KEY_SIZE + P384_PUBLIC_KEY_SIZE + P384_ECDSA_SIGNATURE_SIZE;
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
}

/// Secret NIST P-384 identity (also contains public).
///
/// The master signing key is optional to allow it to be removed and placed in cold storage.
/// It's only needed if the identity is to have its regular working keys upgraded.
pub struct IdentitySecret {
    pub public: Identity,
    pub master_signing_key: Option<P384KeyPair>,
    pub ecdh: P384KeyPair,
    pub ecdsa: P384KeyPair,
}

impl PartialEq for IdentitySecret {
    #[inline(always)]
    fn eq(&self, other: &Self) -> bool {
        self.public == other.public
    }
}

impl Eq for IdentitySecret {}

impl Clone for IdentitySecret {
    fn clone(&self) -> Self {
        Self::from_bytes(self.to_bytes_on_stack::<2048>().as_bytes()).unwrap()
    }
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct IdentitySecretSerialized {
    #[zeroize(skip)]
    a: Address,
    #[zeroize(skip)]
    pm: Blob<P384_PUBLIC_KEY_SIZE>,
    sm: Option<Blob<P384_SECRET_KEY_SIZE>>,
    #[zeroize(skip)]
    ts: u64,
    #[zeroize(skip)]
    p0: Blob<P384_PUBLIC_KEY_SIZE>,
    s0: Blob<P384_SECRET_KEY_SIZE>,
    #[zeroize(skip)]
    p1: Blob<P384_PUBLIC_KEY_SIZE>,
    s1: Blob<P384_SECRET_KEY_SIZE>,
    #[zeroize(skip)]
    ms: Blob<P384_ECDSA_SIGNATURE_SIZE>,
}

impl Serialize for IdentitySecret {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut tmp = IdentitySecretSerialized {
            a: self.public.address,
            pm: (*self.public.master_signing_key.as_bytes()).into(),
            sm: None,
            ts: self.public.timestamp,
            p0: (*self.public.ecdh.as_bytes()).into(),
            s0: Blob::default(),
            p1: (*self.public.ecdsa.as_bytes()).into(),
            s1: Blob::default(),
            ms: self.public.master_signature.into(),
        };
        self.ecdh.secret_key_bytes(&mut tmp.s0);
        self.ecdsa.secret_key_bytes(&mut tmp.s1);
        if let Some(ecdsa) = self.master_signing_key.as_ref() {
            tmp.sm = Some(Blob::default());
            ecdsa.secret_key_bytes(tmp.sm.as_mut().unwrap());
        }
        tmp.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for IdentitySecret {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let d = <IdentitySecretSerialized>::deserialize(deserializer)?;
        if let (Some(pm), Some(ecdh), Some(ecdsa)) = (
            P384PublicKey::from_bytes(d.pm.as_bytes()),
            P384KeyPair::from_bytes(d.p0.as_bytes(), d.s0.as_bytes()),
            P384KeyPair::from_bytes(d.p1.as_bytes(), d.s1.as_bytes()),
        ) {
            let mut master_signing_key_sec = None;
            if let Some(sm) = d.sm.as_ref() {
                if let Some(sm) = P384KeyPair::from_bytes(pm.as_bytes(), sm.as_bytes()) {
                    master_signing_key_sec = Some(sm);
                } else {
                    return Err(serde::de::Error::custom(IDENTITY_ERR.0));
                }
            }
            if let Ok(address) = Address::try_from(SHA384::hash(pm.as_bytes())) {
                if address.eq(&d.a) {
                    let id = Self {
                        public: Identity {
                            address,
                            master_signing_key: pm,
                            timestamp: d.ts,
                            ecdh: ecdh.to_public_key(),
                            ecdsa: ecdsa.to_public_key(),
                            master_signature: *d.ms.as_bytes(),
                        },
                        master_signing_key: master_signing_key_sec,
                        ecdh,
                        ecdsa,
                    };
                    if id.public.locally_validate() {
                        return Ok(id);
                    }
                }
            }
        }
        return Err(serde::de::Error::custom(IDENTITY_ERR.0));
    }
}

impl crate::IdentitySecret for IdentitySecret {
    type Public = Identity;
    type Signature = [u8; 96];

    fn generate(timestamp: u64) -> Self {
        let mut address = Address([0; 6]);
        let mut master_signing_key;
        loop {
            master_signing_key = P384KeyPair::generate();
            *address.as_mut_bytes() = SHA384::hash(master_signing_key.public_key_bytes());
            if address.is_valid() {
                break;
            }
        }

        let ecdh = P384KeyPair::generate();
        let ecdsa = P384KeyPair::generate();

        Self {
            public: Identity {
                address,
                master_signing_key: master_signing_key.to_public_key(),
                timestamp,
                ecdh: ecdh.to_public_key(),
                ecdsa: ecdsa.to_public_key(),
                master_signature: master_signing_key.sign_all(
                    IDENTITY_DOMAIN,
                    &[
                        &timestamp.to_be_bytes(),
                        ecdh.public_key_bytes(),
                        ecdsa.public_key_bytes(),
                    ],
                ),
            },
            master_signing_key: Some(master_signing_key),
            ecdh,
            ecdsa,
        }
    }

    #[inline(always)]
    fn public(&self) -> &Self::Public {
        &self.public
    }

    #[inline(always)]
    fn sign(&self, data: &[u8]) -> Self::Signature {
        self.ecdsa.sign_raw(data)
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

#[cfg(test)]
mod tests {
    use crate::*;
    use zerotier_common_utils::ms_monotonic;

    #[test]
    fn generate() {
        let start = ms_monotonic();
        for _ in 0..3 {
            let secret = p384::IdentitySecret::generate(1);
            println!("P: {}", secret.public.to_string());
        }
        let end = ms_monotonic();
        println!("p384 generation time: {} ms/identity", ((end - start) as f64) / 3.0);
    }

    #[test]
    fn tostring_fromstring() {
        let secret = p384::IdentitySecret::generate(0);
        assert!(p384::Address::from_str(secret.public.address.to_string().as_str())
            .unwrap()
            .eq(&secret.public.address));
        assert!(p384::Identity::from_str(secret.public.to_string().as_str())
            .unwrap()
            .eq(&secret.public));
    }

    #[test]
    fn tobytes_frombytes() {
        let secret = p384::IdentitySecret::generate(0);
        assert!(p384::Address::from_bytes(secret.public.address.to_bytes().as_slice())
            .unwrap()
            .eq(&secret.public.address));
        assert!(p384::Identity::from_bytes(secret.public.to_bytes().as_slice())
            .unwrap()
            .eq(&secret.public));
        assert!(p384::IdentitySecret::from_bytes(secret.to_bytes().as_slice())
            .unwrap()
            .eq(&secret));
    }
}
