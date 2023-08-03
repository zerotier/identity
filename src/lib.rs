/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * (c) ZeroTier, Inc.
 * https://www.zerotier.com/
 */

use std::hash::Hash;
use std::str::FromStr;

use zerotier_common_utils::tofrombytes::ToFromBytes;

/// A unique global identifier for a ZeroTier identity.
pub trait Address: ToString + FromStr + ToFromBytes + Sync + Send + Clone + PartialEq + Eq + Hash + PartialOrd + Ord + AsRef<[u8]> + 'static {
    /// Size of this address in bytes.
    const SIZE: usize;
}

/// A bundle of public key(s) securely identifying a participant on the network.
pub trait Identity: ToString + FromStr + ToFromBytes + Sync + Send + Clone + PartialEq + Eq + Hash + PartialOrd + Ord + 'static {
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
pub trait IdentitySecret: Sync + Send + Clone + PartialEq + Eq + Hash + PartialOrd + Ord + 'static {
    type Public: Identity;

    /// Type returned by sign(), should typically be [u8; Public::SIGNATURE_SIZE].
    /// This could go away if Rust let you reference local constants in traits.
    type Signature;

    /// Generate a new identity.
    /// This may in some cases be a time consuming operation.
    fn generate() -> Self;

    /// Get the public portion of this secret identity.
    fn public(&self) -> &Self::Public;

    /// Cryptographically sign a message with this identity.
    fn sign(&self, data: &[u8]) -> Self::Signature;
}

pub mod p384;
pub mod x25519;

//mod address;
//mod signature;

//pub mod identity;
//pub mod identitysecret;

//pub use address::Address;
//pub use identity::Identity;
//pub use identitysecret::IdentitySecret;
//pub use signature::Signature;

/*
#[cfg(test)]
mod tests {
    use super::*;
    use zerotier_utils::tofrombytes::ToFromBytes;

    #[test]
    fn identity_generate_sign_verify_serialize_deserialize() {
        let id0 = IdentitySecret::generate_x25519();
        let id1 = IdentitySecret::generate_x25519p384(1, None).unwrap();
        let id2 = IdentitySecret::generate_p384(1);

        let sig_data = "hello".as_bytes();
        let sig_wrong_data = "goodbye".as_bytes();

        let sig0 = id0.sign(sig_data);
        let sig1 = id1.sign(sig_data);
        let sig2 = id2.sign(sig_data);

        /*
        println!(
            "identity: signature lengths: x25519 {}, x25519p384 {}, p384 {}, p384pqc {}",
            sig0.len(),
            sig1.len(),
            sig2.len(),
            sig3.len()
        );
        */

        assert!(id0.public.verify(sig0.as_ref(), sig_data));
        assert!(id1.public.verify(sig1.as_ref(), sig_data));
        assert!(id2.public.verify(sig2.as_ref(), sig_data));

        assert!(!id0.public.verify(sig0.as_ref(), sig_wrong_data));
        assert!(!id1.public.verify(sig1.as_ref(), sig_wrong_data));
        assert!(!id2.public.verify(sig2.as_ref(), sig_wrong_data));

        let id0_bytes = id0.to_bytes();
        let id1_bytes = id1.to_bytes();
        let id2_bytes = id2.to_bytes();

        /*
        println!(
            "identity: serialized secret lengths: x25519 {}, x25519p384 {}, p384 {}, p384pqc {}",
            id0_bytes.len(),
            id1_bytes.len(),
            id2_bytes.len(),
            id3_bytes.len()
        );
        */

        let id0_de = IdentitySecret::from_bytes(id0_bytes.as_slice()).unwrap();
        let id1_de = IdentitySecret::from_bytes(id1_bytes.as_slice()).unwrap();
        let id2_de = IdentitySecret::from_bytes(id2_bytes.as_slice()).unwrap();

        assert_eq!(id0_de.to_bytes(), id0.to_bytes());
        assert_eq!(id1_de.to_bytes(), id1.to_bytes());
        assert_eq!(id2_de.to_bytes(), id2.to_bytes());

        let id0_bytes = id0.public.to_bytes();
        let id1_bytes = id1.public.to_bytes();
        let id2_bytes = id2.public.to_bytes();

        /*
        println!(
            "identity: serialized public lengths: x25519 {}, x25519p384 {}, p384 {}, p384pqc {}",
            id0_bytes.len(),
            id1_bytes.len(),
            id2_bytes.len(),
            id3_bytes.len()
        );
        */

        let id0_de = Identity::from_bytes(id0_bytes.as_slice()).unwrap();
        let id1_de = Identity::from_bytes(id1_bytes.as_slice()).unwrap();
        let id2_de = Identity::from_bytes(id2_bytes.as_slice()).unwrap();

        assert_eq!(id0_de.to_bytes(), id0.public.to_bytes());
        assert_eq!(id1_de.to_bytes(), id1.public.to_bytes());
        assert_eq!(id2_de.to_bytes(), id2.public.to_bytes());
    }
}
*/
