/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * (c) ZeroTier, Inc.
 * https://www.zerotier.com/
 */
use crate::p384::*;

/// Secret NIST P-384 identity (also contains public).
///
/// The master signing key is optional to allow it to be removed and placed in cold storage.
/// It's only needed if the identity is to have its regular working keys upgraded.
pub struct IdentitySecret {
    pub public: Identity,
    pub master_signing_key: Option<P384KeyPair>,
    pub ecdh: P384KeyPair,
    pub ecdsa: P384KeyPair,
}

impl PartialEq for IdentitySecret {
    #[inline(always)]
    fn eq(&self, other: &Self) -> bool {
        self.public == other.public
    }
}

impl Eq for IdentitySecret {}

impl Clone for IdentitySecret {
    fn clone(&self) -> Self {
        Self::from_bytes(self.to_bytes_on_stack::<2048>().as_bytes()).unwrap()
    }
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct IdentitySecretSerialized {
    #[zeroize(skip)]
    a: Address,
    #[zeroize(skip)]
    pm: Blob<P384_PUBLIC_KEY_SIZE>,
    sm: Option<Blob<P384_SECRET_KEY_SIZE>>,
    #[zeroize(skip)]
    ts: u64,
    #[zeroize(skip)]
    p0: Blob<P384_PUBLIC_KEY_SIZE>,
    s0: Blob<P384_SECRET_KEY_SIZE>,
    #[zeroize(skip)]
    p1: Blob<P384_PUBLIC_KEY_SIZE>,
    s1: Blob<P384_SECRET_KEY_SIZE>,
    #[zeroize(skip)]
    ms: Blob<P384_ECDSA_SIGNATURE_SIZE>,
    #[zeroize(skip)]
    ss: Blob<P384_ECDSA_SIGNATURE_SIZE>,
}

impl Serialize for IdentitySecret {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut tmp = IdentitySecretSerialized {
            a: self.public.address,
            pm: (*self.public.master_signing_key.as_bytes()).into(),
            sm: None,
            ts: self.public.timestamp,
            p0: (*self.public.ecdh.as_bytes()).into(),
            s0: Blob::default(),
            p1: (*self.public.ecdsa.as_bytes()).into(),
            s1: Blob::default(),
            ms: self.public.master_signature.into(),
            ss: self.public.ecdsa_signature.into(),
        };
        self.ecdh.secret_key_bytes(&mut tmp.s0);
        self.ecdsa.secret_key_bytes(&mut tmp.s1);
        if let Some(ecdsa) = self.master_signing_key.as_ref() {
            tmp.sm = Some(Blob::default());
            ecdsa.secret_key_bytes(tmp.sm.as_mut().unwrap());
        }
        tmp.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for IdentitySecret {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let d = <IdentitySecretSerialized>::deserialize(deserializer)?;
        if let (Some(pm), Some(ecdh), Some(ecdsa)) = (
            P384PublicKey::from_bytes(d.pm.as_bytes()),
            P384KeyPair::from_bytes(d.p0.as_bytes(), d.s0.as_bytes()),
            P384KeyPair::from_bytes(d.p1.as_bytes(), d.s1.as_bytes()),
        ) {
            let mut master_signing_key_sec = None;
            if let Some(sm) = d.sm.as_ref() {
                if let Some(sm) = P384KeyPair::from_bytes(pm.as_bytes(), sm.as_bytes()) {
                    master_signing_key_sec = Some(sm);
                } else {
                    return Err(serde::de::Error::custom(IDENTITY_ERR.0));
                }
            }
            if let Ok(address) = Address::try_from(SHA384::hash(pm.as_bytes())) {
                if address.eq(&d.a) {
                    let id = Self {
                        public: Identity {
                            address,
                            master_signing_key: pm,
                            timestamp: d.ts,
                            ecdh: ecdh.to_public_key(),
                            ecdsa: ecdsa.to_public_key(),
                            master_signature: *d.ms.as_bytes(),
                            ecdsa_signature: *d.ss.as_bytes(),
                        },
                        master_signing_key: master_signing_key_sec,
                        ecdh,
                        ecdsa,
                    };
                    if id.public.locally_validate() {
                        return Ok(id);
                    }
                }
            }
        }
        Err(serde::de::Error::custom(IDENTITY_ERR.0))
    }
}

impl crate::IdentitySecret for IdentitySecret {
    type Public = Identity;
    type Signature = [u8; 96];

    fn generate(timestamp: u64) -> Self {
        let mut address = Address([0; 6]);
        let mut master_signing_key;
        loop {
            master_signing_key = P384KeyPair::generate();
            *address.as_mut_bytes() = SHA384::hash(master_signing_key.public_key_bytes());
            if address.is_valid() {
                break;
            }
        }

        let ecdh = P384KeyPair::generate();
        let ecdsa = P384KeyPair::generate();

        let to_sign: &[&[u8]] = &[
            master_signing_key.public_key_bytes(),
            &timestamp.to_be_bytes(),
            ecdh.public_key_bytes(),
            ecdsa.public_key_bytes(),
        ];

        Self {
            public: Identity {
                address,
                master_signing_key: master_signing_key.to_public_key(),
                timestamp,
                ecdh: ecdh.to_public_key(),
                ecdsa: ecdsa.to_public_key(),
                master_signature: master_signing_key.sign_all(DOMAIN_MASTER_SIG, to_sign),
                ecdsa_signature: ecdsa.sign_all(DOMAIN_SUBKEY_SIG, to_sign),
            },
            master_signing_key: Some(master_signing_key),
            ecdh,
            ecdsa,
        }
    }

    #[inline(always)]
    fn public(&self) -> &Self::Public {
        &self.public
    }

    #[inline(always)]
    fn sign(&self, data: &[u8]) -> Self::Signature {
        self.ecdsa.sign_raw(data)
    }

    #[inline(always)]
    fn sign_domain_restricted(&self, domain: &[u8], data: &[u8]) -> Self::Signature {
        self.ecdsa.sign(domain, data)
    }
}

impl ToFromBytes for IdentitySecret {
    fn read_bytes<R: std::io::Read>(r: &mut R) -> std::io::Result<Self> {
        serde_cbor::from_reader(r).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
    }

    fn write_bytes<W: std::io::Write>(&self, w: &mut W) -> std::io::Result<()> {
        serde_cbor::to_writer(w, self).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
    }
}
