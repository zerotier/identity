use crate::p384::*;

/// 128-bit short address prefix.
///
/// Short addresses are primarily for cases where humans need to type addresses or where
/// they need to be mapped onto an IPv6 address. The fully qualified 384-bit address
/// should be preferred if address transfer is automated or via cut/paste.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ShortAddress(pub(crate) [u64; 2]); // treated as [u8; 16]

impl ShortAddress {
    pub const SIZE: usize = 16;

    #[inline(always)]
    pub fn as_bytes(&self) -> &[u8; Self::SIZE] {
        debug_assert_eq!(size_of::<[u8; Self::SIZE]>(), size_of::<Self>());
        unsafe { &*(&self.0 as *const [u64; 2]).cast() }
    }

    #[inline(always)]
    fn as_mut_bytes(&mut self) -> &mut [u8; Self::SIZE] {
        debug_assert_eq!(size_of::<[u8; Self::SIZE]>(), size_of::<Self>());
        unsafe { &mut *(&mut self.0 as *mut [u64; 2]).cast() }
    }

    #[inline(always)]
    fn is_valid(&self) -> bool {
        self.as_bytes()[0] == Address::REQUIRED_PREFIX
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

impl From<ShortAddress> for [u8; 16] {
    #[inline(always)]
    fn from(value: ShortAddress) -> Self {
        unsafe { transmute(value) }
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

impl ToString for ShortAddress {
    fn to_string(&self) -> String {
        let mut s = String::with_capacity(32);
        first_128_to_string(self.as_bytes(), &mut s);
        s
    }
}

impl Debug for ShortAddress {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.to_string().as_str())
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

impl AsRef<[u8]> for ShortAddress {
    #[inline(always)]
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl Hash for ShortAddress {
    #[inline(always)]
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        state.write_usize(self.0[0] as usize)
    }
}

impl PartialOrd for ShortAddress {
    #[inline(always)]
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
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

impl From<ShortAddress> for std::net::Ipv6Addr {
    fn from(value: ShortAddress) -> Self {
        std::net::Ipv6Addr::from(*value.as_bytes())
    }
}
impl From<&ShortAddress> for std::net::Ipv6Addr {
    fn from(value: &ShortAddress) -> Self {
        std::net::Ipv6Addr::from(*value.as_bytes())
    }
}
