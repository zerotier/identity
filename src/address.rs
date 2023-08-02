/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * (c) ZeroTier, Inc.
 * https://www.zerotier.com/
 */

use std::array::TryFromSliceError;
use std::fmt::Debug;
use std::hash::Hash;
use std::mem::{size_of, transmute};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use zerotier_utils::error::InvalidParameterError;
use zerotier_utils::hex::{self, HEX_CHARS};
use zerotier_utils::tofrombytes::ToFromBytes;
use zerotier_utils::{base24, memory};

/// A unique identifier for an identity on the ZeroTier VL1 network
#[repr(transparent)]
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Address(pub(crate) [u8; Self::SIZE]);

impl Address {
    /// The size of a full address, 384 bits.
    pub const SIZE: usize = 48;

    /// The size of a short address.
    pub const SHORT_SIZE: usize = 16;

    /// The size of a legacy ZeroTier One short address.
    pub const LEGACY_SHORT_SIZE: usize = 5;

    /// Legacy ZeroTier One addresses may not begin with 0xff.
    pub const LEGACY_RESERVED_PREFIX: u8 = 0xff;

    #[inline(always)]
    pub(crate) fn new_uninit() -> Self {
        Self([0u8; Self::SIZE])
    }

    #[inline(always)]
    pub fn from_short_bytes(b: &[u8]) -> Option<Self> {
        if b.len() == Self::SHORT_SIZE {
            let mut a = Address([0u8; Self::SIZE]);
            a.0[..Self::SHORT_SIZE].copy_from_slice(b);
            Some(a)
        } else {
            None
        }
    }

    #[inline(always)]
    pub fn as_bytes(&self) -> &[u8; Self::SIZE] {
        &self.0
    }

    #[inline(always)]
    pub fn as_short_bytes(&self) -> &[u8; Self::SHORT_SIZE] {
        memory::array_range::<u8, { Self::SIZE }, 0, { Self::SHORT_SIZE }>(&self.0)
    }

    #[inline(always)]
    pub fn as_legacy_short_bytes(&self) -> &[u8; Self::LEGACY_SHORT_SIZE] {
        memory::array_range::<u8, { Self::SIZE }, 0, { Self::LEGACY_SHORT_SIZE }>(&self.0)
    }

    /// True if this is a full-length 384-bit address.
    #[inline]
    pub fn is_complete(&self) -> bool {
        self.0[Self::SHORT_SIZE..].iter().any(|i| *i != 0)
    }

    /// True if this is a short (128-bit or legacy 40-bit) address.
    #[inline]
    pub fn is_short(&self) -> bool {
        self.0[Self::SHORT_SIZE..].iter().all(|i| *i == 0)
    }

    /// Append a string representation of this address to a mutable string.
    pub fn to_string_append(&self, s: &mut String) {
        let mut i = 0;
        while i < Self::SHORT_SIZE {
            let ii = i + 4;
            if i > 0 {
                s.push('-');
            }
            base24::encode_4to7(&self.0[i..ii], s);
            i = ii;
        }
        if self.is_complete() {
            s.push('.');
            while i < Self::SIZE {
                let ii = i + 4;
                if i > 16 {
                    s.push('-');
                }
                base24::encode_4to7(&self.0[i..ii], s);
                i = ii;
            }
        }
    }

    /// Get the legacy 40-bit ZeroTier One address in the least significant 40 bits of a u64.
    #[cfg(feature = "legacy_zt1")]
    #[inline]
    pub fn to_legacy_short_u64(&self) -> u64 {
        u64::from_be_bytes(self.0[..8].try_into().unwrap()).wrapping_shr(24)
    }

    #[cfg(feature = "legacy_zt1")]
    #[inline]
    pub fn from_legacy_short_u64(i: u64) -> Self {
        let mut a = Self([0u8; Self::SIZE]);
        a.0[..Self::LEGACY_SHORT_SIZE].copy_from_slice(&i.to_be_bytes()[3..]);
        a
    }

    #[cfg(feature = "legacy_zt1")]
    #[inline(always)]
    pub fn from_legacy_short_bytes(b: &[u8]) -> Option<Self> {
        if b.len() == Self::LEGACY_SHORT_SIZE {
            let mut a = Address([0u8; Self::SIZE]);
            a.0[..Self::LEGACY_SHORT_SIZE].copy_from_slice(b);
            Some(a)
        } else {
            None
        }
    }

    /// Output a legacy short ZeroTier One address (first 5 bytes) in string form.
    /// This is only meaningful if this address belongs to an Identity with the appropriate flag set.
    #[cfg(feature = "legacy_zt1")]
    pub fn to_legacy_short_string(&self) -> String {
        let mut s = String::with_capacity(Self::LEGACY_SHORT_SIZE * 2);
        for b in self.0[..Self::LEGACY_SHORT_SIZE].iter() {
            let b = *b;
            s.push(HEX_CHARS[b.wrapping_shr(4) as usize] as char);
            s.push(HEX_CHARS[(b & 0xf) as usize] as char);
        }
        s
    }

    /// Parse a legacy 10-digit hex ZeroTier One address.
    ///
    /// This must be used instead of from_str() to parse these short addresses. None is returned if
    /// the provided address is not valid.
    #[cfg(feature = "legacy_zt1")]
    pub fn from_legacy_short_string(s: &str) -> Result<Address, InvalidParameterError> {
        let i = hex::from_string_u64(s) & 0xffffffffff;
        if i == 0 || s.len() != (Self::LEGACY_SHORT_SIZE * 2) {
            return Err(InvalidParameterError("invalid legacy address"));
        }
        let i = i.to_be_bytes();
        if i[3] == Self::LEGACY_RESERVED_PREFIX {
            return Err(InvalidParameterError("invalid legacy address"));
        }
        let mut a = Address([0u8; Self::SIZE]);
        a.0[..Self::LEGACY_SHORT_SIZE].copy_from_slice(&i[3..]);
        Ok(a)
    }
}

impl From<[u8; Address::SIZE]> for Address {
    #[inline(always)]
    fn from(value: [u8; Address::SIZE]) -> Self {
        Self(value)
    }
}

impl From<&[u8; Address::SIZE]> for &Address {
    #[inline(always)]
    fn from(value: &[u8; Address::SIZE]) -> Self {
        assert_eq!(size_of::<[u8; Address::SIZE]>(), size_of::<Address>());
        unsafe { transmute(value) }
    }
}

impl From<Address> for [u8; Address::SIZE] {
    #[inline(always)]
    fn from(value: Address) -> Self {
        value.0
    }
}

impl From<&Address> for [u8; Address::SIZE] {
    #[inline(always)]
    fn from(value: &Address) -> Self {
        value.0
    }
}

impl TryFrom<&[u8]> for Address {
    type Error = TryFromSliceError;

    #[inline(always)]
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        value.try_into().map(|a| Self(a))
    }
}

impl ToString for Address {
    fn to_string(&self) -> String {
        let mut s = String::with_capacity(96);
        self.to_string_append(&mut s);
        s
    }
}

impl FromStr for Address {
    type Err = InvalidParameterError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut a = Self([0u8; Self::SIZE]);
        let mut i = 0;
        for ss in s.split(&['-', '.']) {
            if ss.len() == 7 {
                for b in base24::decode_7to4(ss.as_bytes())? {
                    if i >= Self::SIZE {
                        return Err(InvalidParameterError("invalid address"));
                    }
                    a.0[i] = b;
                    i += 1;
                }
            } else {
                return Err(InvalidParameterError("invalid address"));
            }
        }
        return Ok(a);
    }
}

impl Debug for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.to_string().as_str())
    }
}

impl ToFromBytes for Address {
    #[inline(always)]
    fn read_bytes<R: std::io::Read>(r: &mut R) -> std::io::Result<Self> {
        let mut tmp = Address([0u8; Self::SIZE]);
        r.read_exact(&mut tmp.0)?;
        Ok(tmp)
    }

    #[inline(always)]
    fn from_bytes(b: &[u8]) -> std::io::Result<Self> {
        Ok(Self(
            b.try_into()
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "invalid address"))?,
        ))
    }

    #[inline(always)]
    fn write_bytes<W: std::io::Write>(&self, w: &mut W) -> std::io::Result<()> {
        w.write_all(&self.0)
    }

    #[inline(always)]
    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl Hash for Address {
    #[inline(always)]
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        state.write(&self.0[..8])
    }
}

impl Serialize for Address {
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            self.to_string().serialize(serializer)
        } else {
            serializer.serialize_bytes(&self.0)
        }
    }
}

struct AddressDeserializeVisitor;

impl<'de> serde::de::Visitor<'de> for AddressDeserializeVisitor {
    type Value = Address;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("ZeroTier address")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Address::from_str(v.trim()).map_err(|e| serde::de::Error::custom(e.to_string()))
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        v.try_into()
            .map(|b| Address(b))
            .map_err(|_| serde::de::Error::invalid_length(v.len(), &self))
    }
}

impl<'de> Deserialize<'de> for Address {
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            deserializer.deserialize_str(AddressDeserializeVisitor)
        } else {
            deserializer.deserialize_bytes(AddressDeserializeVisitor)
        }
    }
}
