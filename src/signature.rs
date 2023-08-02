/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * (c) ZeroTier, Inc.
 * https://www.zerotier.com/
 */

use zerotier_crypto::p384::P384_ECDSA_SIGNATURE_SIZE;
use zerotier_crypto::x25519::ED25519_SIGNATURE_SIZE;
use zerotier_utils::arrayvec::ArrayVec;

/// Buffer type large enough to store any possible signature combination.
/// This can be enlarged if necessary.
pub type Signature = ArrayVec<u8, 192>;

const SIGNATURE_FLAG_ECDSA_P384: u8 = 0x01;
const SIGNATURE_FLAG_EDDSA_ED25519: u8 = 0x02;

pub(crate) fn make_signature(ecdsa_p384: &[u8], eddsa_ed25519: &[u8]) -> Signature {
    let mut s = Signature::new();
    s.push(0);
    let mut flags = 0;

    if ecdsa_p384.len() == P384_ECDSA_SIGNATURE_SIZE {
        flags |= SIGNATURE_FLAG_ECDSA_P384;
        s.push_slice(ecdsa_p384);
    }
    if eddsa_ed25519.len() == ED25519_SIGNATURE_SIZE {
        flags |= SIGNATURE_FLAG_EDDSA_ED25519;
        s.push_slice(eddsa_ed25519);
    }

    s.as_mut()[0] = flags;
    s
}

/// Returns which signatures are present: (p384, ed25519)
pub(crate) fn parse_signature(mut s: &[u8]) -> (Option<&[u8]>, Option<&[u8]>) {
    let mut sigs = (None, None);

    if !s.is_empty() {
        let flags = s[0];
        s = &s[1..];
        if (flags & SIGNATURE_FLAG_ECDSA_P384) != 0 {
            if s.len() >= P384_ECDSA_SIGNATURE_SIZE {
                sigs.0 = Some(&s[..P384_ECDSA_SIGNATURE_SIZE]);
                s = &s[P384_ECDSA_SIGNATURE_SIZE..];
            }
        }
        if (flags & SIGNATURE_FLAG_EDDSA_ED25519) != 0 {
            if s.len() >= ED25519_SIGNATURE_SIZE {
                sigs.1 = Some(&s[..ED25519_SIGNATURE_SIZE]);
                //s = &s[ED25519_SIGNATURE_SIZE..];
            }
        }
    }

    sigs
}
