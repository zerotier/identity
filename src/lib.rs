/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * (c) ZeroTier, Inc.
 * https://www.zerotier.com/
 */

use std::hash::Hash;
use std::str::FromStr;

use serde::de::DeserializeOwned;
use serde::Serialize;

use zerotier_common_utils::error::InvalidParameterError;
use zerotier_common_utils::tofrombytes::ToFromBytes;

/// A unique global identifier for a ZeroTier identity.
pub trait Address:
    ToString
    + FromStr
    + ToFromBytes
    + Sync
    + Send
    + Clone
    + PartialEq
    + Eq
    + Hash
    + PartialOrd
    + Ord
    + AsRef<[u8]>
    + 'static
{
    /// Size of this address in bytes.
    const SIZE: usize;
}

/// A bundle of public key(s) securely identifying a participant on the network.
pub trait Identity:
    ToString + FromStr + ToFromBytes + Sync + Send + Clone + PartialEq + Eq + Hash + PartialOrd + Ord + 'static
{
    /// Number of bytes in this identity's byte serialized representation.
    const SIZE: usize;

    /// Number of bytes in a signature from this identity.
    const SIGNATURE_SIZE: usize;

    /// Secret type corresponding to this identity.
    type Secret: IdentitySecret;

    /// Verify a signature made by this identity's corresponding secret.
    fn verify_signature(&self, data: &[u8], signature: &[u8]) -> bool;
}

/// Secret keys that correspond to a public Identity.
pub trait IdentitySecret: Sync + Send + Clone + PartialEq + Eq + Serialize + DeserializeOwned + 'static {
    type Public: Identity;

    /// Type returned by sign(), should typically be [u8; Public::SIGNATURE_SIZE].
    /// This could go away if Rust let you reference local constants in traits.
    type Signature;

    /// Generate a new identity.
    /// This may in some cases be a time consuming operation.
    fn generate(timestamp: u64) -> Self;

    /// Get the public portion of this secret identity.
    fn public(&self) -> &Self::Public;

    /// Cryptographically sign a message with this identity.
    fn sign(&self, data: &[u8]) -> Self::Signature;
}

mod base24;
mod base62;
pub mod p384;
pub mod x25519;

pub(crate) const ADDRESS_ERR: InvalidParameterError = InvalidParameterError("invalid address");
pub(crate) const IDENTITY_ERR: InvalidParameterError = InvalidParameterError("invalid identity");

// Dependency re-export
pub use serde;
pub use serde_cbor;
pub use zeroize;
pub use zerotier_crypto_glue;
pub use zerotier_common_utils;
pub use zerotier_crypto_glue::zssp;
