/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * (c) ZeroTier, Inc.
 * https://www.zerotier.com/
 */
use crate::p384::*;

#[derive(Debug, Clone, Hash)]
pub enum PeerIdentifier {
    Identity(Identity),
    Address(Address),
    Short(ShortAddress),
}
#[derive(Debug, Clone, Copy, Hash)]
pub enum PeerIdentifierRef<'a> {
    Identity(&'a Identity),
    Address(&'a Address),
    Short(&'a ShortAddress),
}

#[derive(Debug, Clone, Copy, Hash)]
pub enum AnyAddress {
    Address(Address),
    Short(ShortAddress),
}

impl<'a> PeerIdentifierRef<'a> {
    pub fn matches(self, identity: &Identity) -> bool {
        use PeerIdentifierRef::*;
        match self {
            Identity(id) => (*id).eq(identity),
            Address(id) => identity.address.eq(id),
            Short(id) => identity.address.prefix().eq(id),
        }
    }

    pub fn prefix(&self) -> &ShortAddress {
        use PeerIdentifierRef::*;
        match self {
            Identity(id) => id.address.prefix(),
            Address(id) => id.prefix(),
            Short(id) => id,
        }
    }

    pub fn address(self) -> AnyAddress {
        use PeerIdentifierRef::*;
        match self {
            Identity(id) => id.address.into(),
            Address(id) => (*id).into(),
            Short(id) => id.into(),
        }
    }

    /// Returns `true` if `other` contains the most complete version of the identity between
    /// `self` and `other`.
    /// Otherwise returns `false`.
    /// This function will debug panic if `self` and `other` are not identifiers for the same peer.
    /// The caller must check for equality before calling this function.
    pub fn upgrade_check(&self, other: &Self) -> bool {
        debug_assert_eq!(self, other);
        use PeerIdentifierRef::*;
        match (self, other) {
            (Identity(id1), Identity(id2)) => id1.timestamp < id2.timestamp,
            (Identity(_), _) => false,
            (_, Identity(_)) => true,
            (Short(_), Address(_)) => true,
            _ => false,
        }
    }

    pub fn write_to_string(&self, s: &mut String, prefix: bool) {
        match self {
            Self::Identity(a) => a.write_to_string(s, prefix),
            Self::Address(a) => a.write_to_string(s, prefix),
            Self::Short(a) => a.write_to_string(s, prefix),
        }
    }
}

impl PeerIdentifier {
    pub fn matches(&self, identity: &Identity) -> bool {
        let r: PeerIdentifierRef = self.into();
        r.matches(identity)
    }

    pub fn prefix(&self) -> &ShortAddress {
        use PeerIdentifier::*;
        match self {
            Identity(id) => id.address.prefix(),
            Address(id) => id.prefix(),
            Short(id) => id,
        }
    }

    pub fn address(&self) -> AnyAddress {
        let r: PeerIdentifierRef = self.into();
        r.address()
    }

    /// Returns `true` if `other` contains the most complete version of the identity between
    /// `self` and `other`.
    /// Otherwise returns `false`.
    /// This function will debug panic if `self` and `other` are not identifiers for the same peer.
    /// The caller must check for equality before calling this function.
    /// TODO: make this function take into account identity lifetime.
    pub fn upgrade_check(&self, other: &Self) -> bool {
        let r: PeerIdentifierRef = self.into();
        r.upgrade_check(&other.into())
    }

    pub fn write_to_string(&self, s: &mut String, prefix: bool) {
        match self {
            Self::Identity(a) => a.write_to_string(s, prefix),
            Self::Address(a) => a.write_to_string(s, prefix),
            Self::Short(a) => a.write_to_string(s, prefix),
        }
    }
}

impl AnyAddress {
    pub fn matches(&self, identity: &Identity) -> bool {
        match self {
            AnyAddress::Address(id) => identity.address.eq(id),
            AnyAddress::Short(id) => identity.address.prefix().eq(id),
        }
    }

    pub fn prefix(&self) -> &ShortAddress {
        match self {
            AnyAddress::Address(id) => id.prefix(),
            AnyAddress::Short(id) => id,
        }
    }
    /// Returns `true` if `other` contains the most complete version of the identity between
    /// `self` and `other`.
    /// Otherwise returns `false`.
    /// This function will debug panic if `self` and `other` are not identifiers for the same peer.
    /// The caller must check for equality before calling this function.
    /// TODO: make this function take into account identity lifetime.
    pub fn upgrade_check(&self, other: &Self) -> bool {
        debug_assert_eq!(self, other);
        use AnyAddress::*;
        match (self, other) {
            (Short(_), Address(_)) => true,
            _ => false,
        }
    }

    pub fn write_to_string(&self, s: &mut String, prefix: bool) {
        match self {
            Self::Address(a) => a.write_to_string(s, prefix),
            Self::Short(a) => a.write_to_string(s, prefix),
        }
    }
}

/// Does not preserve transitivity.
impl<'a> PartialEq for PeerIdentifierRef<'a> {
    fn eq(&self, other: &Self) -> bool {
        use PeerIdentifierRef::*;
        match (self, other) {
            (Identity(identity), id) | (id, Identity(identity)) => id.matches(identity),
            (Address(addr0), Address(addr1)) => addr0.eq(addr1),
            (Address(addr0), Short(addr1)) => addr0.prefix().eq(addr1),
            (Short(addr0), Address(addr1)) => (*addr0).eq(addr1.prefix()),
            (Short(addr0), Short(addr1)) => addr0.eq(addr1),
        }
    }
}
/// Does not preserve transitivity.
impl PartialEq for PeerIdentifier {
    fn eq(&self, other: &Self) -> bool {
        let r: PeerIdentifierRef = self.into();
        r.eq(&other.into())
    }
}
/// Does not preserve transitivity.
impl PartialEq for AnyAddress {
    fn eq(&self, other: &Self) -> bool {
        use AnyAddress::*;
        match (self, other) {
            (Address(addr0), Address(addr1)) => addr0.eq(addr1),
            (Address(addr0), Short(addr1)) => addr0.prefix().eq(addr1),
            (Short(addr0), Address(addr1)) => addr0.eq(addr1.prefix()),
            (Short(addr0), Short(addr1)) => addr0.eq(addr1),
        }
    }
}

impl<'a> ToString for PeerIdentifierRef<'a> {
    fn to_string(&self) -> String {
        match self {
            Self::Identity(id) => id.to_string(),
            Self::Address(addr) => addr.to_string(),
            Self::Short(addr) =>  addr.to_string(),
        }
    }
}
impl ToString for PeerIdentifier {
    fn to_string(&self) -> String {
        match self {
            Self::Identity(id) => id.to_string(),
            Self::Address(addr) => addr.to_string(),
            Self::Short(addr) =>  addr.to_string(),
        }
    }
}
impl ToString for AnyAddress {
    fn to_string(&self) -> String {
        match self {
            Self::Address(addr) => addr.to_string(),
            Self::Short(addr) =>  addr.to_string(),
        }
    }
}
impl FromStr for PeerIdentifier {
    type Err = InvalidParameterError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let l = s.len();
        if l >= Identity::STRING_SIZE {
            Identity::from_str(s).map(Self::Identity)
        } else if l >= Address::STRING_SIZE {
            Address::from_str(s).map(Self::Address)
        } else {
            ShortAddress::from_str(s).map(Self::Short)
        }
    }
}
impl FromStr for AnyAddress {
    type Err = InvalidParameterError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let l = s.len();
        if l >= Address::STRING_SIZE {
            Address::from_str(s).map(Self::Address)
        } else {
            ShortAddress::from_str(s).map(Self::Short)
        }
    }
}

impl<'a> serde::Serialize for PeerIdentifierRef<'a> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Identity(id) => id.serialize(s),
            Self::Address(addr) => addr.serialize(s),
            Self::Short(addr) =>  addr.serialize(s),
        }
    }
}
impl serde::Serialize for PeerIdentifier {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Identity(id) => id.serialize(s),
            Self::Address(addr) => addr.serialize(s),
            Self::Short(addr) =>  addr.serialize(s),
        }
    }
}
impl serde::Serialize for AnyAddress {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Address(addr) => addr.serialize(s),
            Self::Short(addr) =>  addr.serialize(s),
        }
    }
}

impl<'de> Deserialize<'de> for PeerIdentifier {
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            Self::from_str(<&str>::deserialize(deserializer)?).map_err(|_| serde::de::Error::custom(ADDRESS_ERR.0))
        } else {
            struct Visitor;

            impl<'de> serde::de::Visitor<'de> for Visitor {
                type Value = PeerIdentifier;

                fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                    formatter.write_str("a zerotier identifier")
                }

                fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Self::Value, E>
                {
                    match v.len() {
                        Identity::SIZE => Identity::from_bytes(v).map(Self::Value::Identity),
                        Address::SIZE => Address::from_bytes(v).map(Self::Value::Address),
                        ShortAddress::SIZE => ShortAddress::from_bytes(v).map(Self::Value::Short),
                        _ => return Err(serde::de::Error::custom(ADDRESS_ERR.0))
                    }
                    .map_err(|_| serde::de::Error::custom(ADDRESS_ERR.0))
                }
            }
            deserializer.deserialize_bytes(Visitor)
        }
    }
}
impl<'de> Deserialize<'de> for AnyAddress {
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            Self::from_str(<&str>::deserialize(deserializer)?).map_err(|_| serde::de::Error::custom(ADDRESS_ERR.0))
        } else {
            struct Visitor;

            impl<'de> serde::de::Visitor<'de> for Visitor {
                type Value = AnyAddress;

                fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                    formatter.write_str("a zerotier identifier")
                }

                fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Self::Value, E>
                {
                    match v.len() {
                        Address::SIZE => Address::from_bytes(v).map(Self::Value::Address),
                        ShortAddress::SIZE => ShortAddress::from_bytes(v).map(Self::Value::Short),
                        _ => return Err(serde::de::Error::custom(ADDRESS_ERR.0))
                    }
                    .map_err(|_| serde::de::Error::custom(ADDRESS_ERR.0))
                }
            }
            deserializer.deserialize_bytes(Visitor)
        }
    }
}


/* Start of Conversions */

impl<'a> From<&'a PeerIdentifier> for PeerIdentifierRef<'a> {
    #[inline]
    fn from(value: &'a PeerIdentifier) -> Self {
        match value {
            PeerIdentifier::Identity(v) => PeerIdentifierRef::Identity(v),
            PeerIdentifier::Address(v) => PeerIdentifierRef::Address(v),
            PeerIdentifier::Short(v) => PeerIdentifierRef::Short(v),
        }
    }
}
impl<'a> From<PeerIdentifierRef<'a>> for PeerIdentifier {
    #[inline]
    fn from(value: PeerIdentifierRef<'a>) -> Self {
        match value {
            PeerIdentifierRef::Identity(v) => PeerIdentifier::Identity(v.clone()),
            PeerIdentifierRef::Address(v) => PeerIdentifier::Address(*v),
            PeerIdentifierRef::Short(v) => PeerIdentifier::Short(*v),
        }
    }
}

impl From<AnyAddress> for PeerIdentifier {
    #[inline]
    fn from(value: AnyAddress) -> Self {
        match value {
            AnyAddress::Address(v) => PeerIdentifier::Address(v),
            AnyAddress::Short(v) => PeerIdentifier::Short(v),
        }
    }
}
impl From<&AnyAddress> for PeerIdentifier {
    #[inline]
    fn from(value: &AnyAddress) -> Self {
        match value {
            AnyAddress::Address(v) => PeerIdentifier::Address(*v),
            AnyAddress::Short(v) => PeerIdentifier::Short(*v),
        }
    }
}
impl<'a> From<&'a AnyAddress> for PeerIdentifierRef<'a> {
    #[inline]
    fn from(value: &'a AnyAddress) -> Self {
        match value {
            AnyAddress::Address(v) => PeerIdentifierRef::Address(v),
            AnyAddress::Short(v) => PeerIdentifierRef::Short(v),
        }
    }
}

macro_rules! impl_from {
    ($ft:ident for $tt:ident::$ev:ident) => {
        impl From<$ft> for $tt {
            #[inline]
            fn from(v: $ft) -> Self {
                Self::$ev(v)
            }
        }
        impl From<&$ft> for $tt {
            #[inline]
            fn from(v: &$ft) -> Self {
                Self::$ev(v.clone())
            }
        }
    };
}

impl_from!(Address for PeerIdentifier::Address);
impl_from!(ShortAddress for PeerIdentifier::Short);
impl_from!(Identity for PeerIdentifier::Identity);
impl_from!(Address for AnyAddress::Address);
impl_from!(ShortAddress for AnyAddress::Short);

impl<'a> From<&'a Address> for PeerIdentifierRef<'a> {
    fn from(value: &'a Address) -> Self {
        Self::Address(value)
    }
}
impl<'a> From<&'a ShortAddress> for PeerIdentifierRef<'a> {
    fn from(value: &'a ShortAddress) -> Self {
        Self::Short(value)
    }
}
impl<'a> From<&'a Identity> for PeerIdentifierRef<'a> {
    fn from(value: &'a Identity) -> Self {
        Self::Identity(value)
    }
}
