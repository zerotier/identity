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
#[derive(Debug, Clone, Hash)]
pub enum PeerIdentifierRef<'a> {
    Identity(&'a Identity),
    Address(&'a Address),
    Short(ShortAddress),
}

impl PeerIdentifier {
    pub fn matches(&self, identity: &Identity) -> bool {
        match self {
            PeerIdentifier::Identity(id) => id.eq(identity),
            PeerIdentifier::Address(id) => identity.address.eq(id),
            PeerIdentifier::Short(id) => identity.address.prefix().eq(id),
        }
    }

    pub fn prefix(&self) -> &ShortAddress {
        match self {
            PeerIdentifier::Identity(id) => id.address.prefix(),
            PeerIdentifier::Address(id) => id.prefix(),
            PeerIdentifier::Short(id) => id,
        }
    }

    pub fn address(&self) -> AnyAddress {
        match self {
            PeerIdentifier::Identity(id) => id.address.into(),
            PeerIdentifier::Address(id) => id.into(),
            PeerIdentifier::Short(id) => id.into(),
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
        use PeerIdentifier::*;
        match (self, other) {
            (Identity(_), _) => false,
            (_, Identity(_)) => true,
            (Short(_), Address(_)) => true,
            _ => false,
        }
    }
}
/// Does not preserve transitivity.
impl std::cmp::PartialEq for PeerIdentifier {
    fn eq(&self, other: &Self) -> bool {
        use PeerIdentifier::*;
        match (self, other) {
            (Identity(identity), id) | (id, Identity(identity)) => id.matches(identity),
            (Address(addr0), Address(addr1)) => addr0.eq(addr1),
            (Address(addr0), Short(addr1)) => addr0.prefix().eq(addr1),
            (Short(addr0), Address(addr1)) => addr0.eq(addr1.prefix()),
            (Short(addr0), Short(addr1)) => addr0.eq(addr1),
        }
    }
}
impl From<Address> for PeerIdentifier {
    fn from(value: Address) -> Self {
        Self::Address(value)
    }
}
impl From<ShortAddress> for PeerIdentifier {
    fn from(value: ShortAddress) -> Self {
        Self::Short(value)
    }
}
impl From<&Address> for PeerIdentifier {
    fn from(value: &Address) -> Self {
        Self::Address(*value)
    }
}
impl From<&ShortAddress> for PeerIdentifier {
    fn from(value: &ShortAddress) -> Self {
        Self::Short(*value)
    }
}

impl From<Identity> for PeerIdentifier {
    fn from(value: Identity) -> Self {
        Self::Identity(value)
    }
}

#[derive(serde::Deserialize, serde::Serialize, Debug, Clone, Copy, Hash)]
pub enum AnyAddress {
    Address(Address),
    Short(ShortAddress),
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
}
/// Does not preserve transitivity.
impl std::cmp::PartialEq for AnyAddress {
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
impl From<Address> for AnyAddress {
    fn from(value: Address) -> Self {
        Self::Address(value)
    }
}
impl From<ShortAddress> for AnyAddress {
    fn from(value: ShortAddress) -> Self {
        Self::Short(value)
    }
}
impl From<&Address> for AnyAddress {
    fn from(value: &Address) -> Self {
        Self::Address(*value)
    }
}
impl From<&ShortAddress> for AnyAddress {
    fn from(value: &ShortAddress) -> Self {
        Self::Short(*value)
    }
}
