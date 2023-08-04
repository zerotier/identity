/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * (c) ZeroTier, Inc.
 * https://www.zerotier.com/
 */

use zerotier_common_utils::error::InvalidParameterError;

/// All unambiguous letters, thus easy to type on the alphabetic keyboards on phones without extra shift taps.
/// The letters 'l' and 'u' are skipped.
const BASE24_ALPHABET: [u8; 24] = [
    b'a', b'b', b'c', b'd', b'e', b'f', b'g', b'h', b'i', b'j', b'k', b'm', b'n', b'o', b'p', b'q', b'r', b's', b't', b'v', b'w', b'x', b'y', b'z',
];

/// Reverse table for BASE24 alphabet, indexed relative to 'a' or 'A'.
const BASE24_ALPHABET_INV: [u8; 26] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 255, 11, 12, 13, 14, 15, 16, 17, 18, 255, 19, 20, 21, 22, 23,
];

/// Encode 4 binary bytes into 7 base24 characters.
pub fn encode_4to7(b: &[u8], s: &mut String) {
    let mut n = u32::from_be_bytes(b[..4].try_into().unwrap());
    for _ in 0..6 {
        let (d, r) = (n / 24, n % 24);
        n = d;
        s.push(BASE24_ALPHABET[r as usize] as char);
    }
    s.push(BASE24_ALPHABET[n as usize] as char);
}

pub fn decode_7to4(mut s: &[u8]) -> Result<[u8; 4], InvalidParameterError> {
    let mut n = 0u32;
    if s.len() > 7 {
        s = &s[..7];
    }
    for c in s.iter().rev() {
        let mut c = *c;
        if c >= 97 && c <= 122 {
            c -= 97;
        } else if c >= 65 && c <= 90 {
            c -= 65;
        } else {
            return Err(InvalidParameterError("invalid base24"));
        }
        let i = BASE24_ALPHABET_INV[c as usize];
        if i == 255 {
            return Err(InvalidParameterError("invalid base24"));
        }
        n *= 24;
        n = n.wrapping_add(i as u32);
    }
    return Ok(n.to_be_bytes());
}
