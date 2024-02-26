/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * (c) ZeroTier, Inc.
 * https://www.zerotier.com/
 */
use crate::p384::*;

// Implementation note: the addresses use u64 arrays that are actually treated as flat byte
// array memory arenas in order to optimize for fast lookup when these are used as map keys.
// This reduces the number of instructions required to perform equality comparisons and
// simplifies the implementation of Hash. The effect is small but might matter at scale.

/// 384-bit ZeroTier address.
/// An address is the SHA384(public master signing key) of an identity.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Address(pub(crate) [u64; 6]); // treated as [u8; 48]

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
    pub(crate) fn as_mut_bytes(&mut self) -> &mut [u8; 48] {
        debug_assert_eq!(size_of::<[u8; 48]>(), size_of::<Self>());
        unsafe { &mut *self.0.as_mut_ptr().cast::<[u8; 48]>() }
    }

    /// Check address validity, used in deserialization code.
    #[inline(always)]
    pub(crate) fn is_valid(&self) -> bool {
        self.as_bytes()[0] == Self::REQUIRED_PREFIX
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

impl From<Address> for [u8; 48] {
    #[inline(always)]
    fn from(value: Address) -> Self {
        unsafe { transmute(value) }
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

impl Debug for Address {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.to_string().as_str())
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

impl AsRef<[u8]> for Address {
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

impl PartialOrd for Address {
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

impl crate::Address for Address {
    const SIZE: usize = 48;
}
