/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * (c) ZeroTier, Inc.
 * https://www.zerotier.com/
 */

use zerotier_common_utils::error::InvalidParameterError;

pub fn encode_8to11(mut n: u64, s: &mut String) {
    for _ in 0..11 {
        let (d, r) = (n / 62, n % 62);
        n = d;
        let r = r as u8;
        s.push(if r < 26 {
            r + 97 // a..z
        } else if r < 52 {
            r + 39 // A..Z
        } else {
            r - 4 // 0..9
        } as char);
    }
}

pub fn decode_11to8(s: &[u8]) -> Result<u64, InvalidParameterError> {
    let mut n = 0u64;
    for c in s.iter().rev() {
        let c = *c;
        n *= 62;
        n = n.wrapping_add(if c >= 97 && c <= 122 {
            c - 97
        } else if c >= 65 && c <= 90 {
            c - 39
        } else if c >= 48 && c <= 57 {
            c + 4
        } else {
            return Err(InvalidParameterError("invalid base62"));
        } as u64);
    }
    return Ok(n);
}

#[cfg(test)]
mod tests {
    use zerotier_crypto_glue::random::{rand_core::RngCore, SecureRandom};

    use super::*;

    #[test]
    fn base62_encode_decode() {
        let mut tmp = String::with_capacity(16);
        for _ in 0..10000 {
            let r = SecureRandom.next_u64();
            tmp.clear();
            encode_8to11(r, &mut tmp);
            assert_eq!(decode_11to8(tmp.as_bytes()).unwrap(), r);
        }
    }
}
