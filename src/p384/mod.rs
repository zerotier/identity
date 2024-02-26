/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * (c) ZeroTier, Inc.
 * https://www.zerotier.com/
 */

use std::fmt::Debug;
use std::hash::Hash;
use std::io::Write;
use std::mem::{size_of, transmute};
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::zeroize::{Zeroize, ZeroizeOnDrop};
use zerotier_common_utils::{base64, blob::Blob, error::InvalidParameterError, tofrombytes::ToFromBytes};
use zerotier_crypto_glue::{hash::SHA384, p384::*};

use crate::base24;
use crate::{ADDRESS_ERR, IDENTITY_ERR};

mod address;
mod identity;
mod identity_secret;
mod short_address;

pub use address::*;
pub use identity::*;
pub use identity_secret::*;
pub use short_address::*;

pub(crate) const DOMAIN_MASTER_SIG: &[u8] = b"ZTID_MASTERSIG_P384";
pub(crate) const DOMAIN_SUBKEY_SIG: &[u8] = b"ZTID_SUBKEYSIG_P384";

fn first_128_to_string(b: &[u8], s: &mut String) {
    base24::encode_4to7(&b[0..4], s);
    s.push('.');
    base24::encode_4to7(&b[4..8], s);
    s.push('.');
    base24::encode_4to7(&b[8..12], s);
    s.push('.');
    base24::encode_4to7(&b[12..16], s);
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
