ZeroTier Cryptographic Identity
======

This is the cryptographic identity implementation for the next generation of ZeroTier. It contains common traits for addresses and identities and two implementations: `x25519` with 40-bit addresses for ZeroTier V1 compatibility and `p384` with 384-bit addresses for the future.

P384 identities have 384-bit (SHA384) based addresses with 128-bit short prefixes that will be used when humans have to type them. SHA384 was chosen over the more common SHA256 [due to CNSA hash length recommendations](https://media.defense.gov/2022/Sep/07/2003071836/-1/-1/0/CSI_CNSA_2.0_FAQ_.PDF). NIST P-384 as well as SHA2 were chosen over alternatives like Curve25519 and Blake hashes because FIPS/NIST compliance is a design goal for the future of ZeroTier.

Here's what a fully qualified 384-bit ZeroTier address looks like:

    fxfigey.cdddyst.zfnedeq.enookwh.v5hEQtREECrEmu8QqNYOsdydKvTZIFeummABSzEvi8tq

The first four elements are the first 128 bits rendered as four 7-digit base24 numbers. Base24 was chosen because its alphabet can be easily typed on all keyboards including mobile phone keyboards (without shifting), and groups of 7 digits are used [because this number is convenient for humans](https://blog.codinghorror.com/the-magical-number-seven-plus-or-minus-two/) and the whole point of short prefixes is for cases where humans need to manually enter them. The fully qualfied 384-bit form is preferred whenever possible, such as when copying and pasting or using QR codes or URLs.

After the initial 128 bits is the remaining 256 bits of the address encoded using base62. Base62 is used instead of base64 to avoid using non-alphanumeric characters that cause issues with highlighting in terminals or encoding in URLs and filenames.
