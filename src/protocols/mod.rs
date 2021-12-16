#![allow(non_snake_case)]
/*
    Multisig ed25519

    Copyright 2018 by Kzen Networks

    This file is part of Multisig Schnorr library
    (https://github.com/KZen-networks/multisig-schnorr)

    Multisig Schnorr is free software: you can redistribute
    it and/or modify it under the terms of the GNU General Public
    License as published by the Free Software Foundation, either
    version 3 of the License, or (at your option) any later version.

    @license GPL-3.0+ <https://github.com/KZen-networks/multi-party-ed25519/blob/master/LICENSE>
*/
use curv::arithmetic::Converter;
use curv::cryptographic_primitives::proofs::ProofError;
use curv::elliptic::curves::{Ed25519, Point, Scalar};
use curv::BigInt;
use rand::{thread_rng, Rng};
use sha2::{Digest, Sha512};

// simple ed25519 based on rfc8032
// reference implementation: https://ed25519.cr.yp.to/python/ed25519.py
pub mod aggsig;
pub mod multisig;
pub mod thresholdsig;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExpendedPrivateKey {
    pub prefix: Scalar<Ed25519>,
    private_key: Scalar<Ed25519>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExpendedKeyPair {
    pub public_key: Point<Ed25519>,
    expended_private_key: ExpendedPrivateKey,
}

impl ExpendedKeyPair {
    pub fn create() -> ExpendedKeyPair {
        let secret = thread_rng().gen();
        Self::create_from_private_key(secret)
    }

    pub fn create_from_private_key(secret: [u8; 32]) -> ExpendedKeyPair {
        let h = Sha512::new().chain(secret).finalize();
        let mut private_key: [u8; 32] = [0u8; 32];
        let mut prefix: [u8; 32] = [0u8; 32];
        prefix.copy_from_slice(&h[32..64]);
        private_key.copy_from_slice(&h[0..32]);
        private_key[0] &= 248;
        private_key[31] &= 63;
        private_key[31] |= 64;
        let private_key = Scalar::from_bytes(&private_key)
            .expect("private_key is the right length, so can't fail");
        let prefix = Scalar::from_bytes(&prefix).expect("prefix is the right, so can't fail");
        let public_key = Point::generator() * &private_key;
        ExpendedKeyPair {
            public_key,
            expended_private_key: ExpendedPrivateKey {
                prefix,
                private_key,
            },
        }
    }
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Signature {
    pub R: Point<Ed25519>,
    pub s: Scalar<Ed25519>,
}

impl Signature {
    pub fn verify(&self, message: &[u8], public_key: &Point<Ed25519>) -> Result<(), ProofError> {
        let k = Self::k(&self.R, public_key, message);
        let A = public_key;

        let kA = A * k;
        let R_plus_kA = kA + &self.R;
        let sG = &self.s * Point::generator();

        if R_plus_kA == sG {
            Ok(())
        } else {
            Err(ProofError)
        }
    }

    pub(crate) fn k(R: &Point<Ed25519>, PK: &Point<Ed25519>, message: &[u8]) -> Scalar<Ed25519> {
        let mut k = Sha512::new()
            .chain(&*R.to_bytes(true))
            .chain(&*PK.to_bytes(true))
            .chain(message)
            .finalize();
        // reverse because BigInt uses BigEndian.
        k.reverse();
        Scalar::from_bigint(&BigInt::from_bytes(&k))
    }
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use curv::elliptic::curves::{Point, Scalar};
    use rand_xoshiro::rand_core::{RngCore, SeedableRng};
    use rand_xoshiro::Xoshiro256PlusPlus;

    use protocols::{ExpendedKeyPair, Signature};

    #[test]
    fn test_generate_pubkey_dalek() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        println!("test_generate_pubkey_dalek seed: {}", now);
        let mut rng = Xoshiro256PlusPlus::seed_from_u64(now as _);

        let mut privkey = [0u8; 32];
        for _ in 0..4096 {
            rng.fill_bytes(&mut privkey);
            let zengo_keypair = ExpendedKeyPair::create_from_private_key(privkey);
            let dalek_secret = ed25519_dalek::SecretKey::from_bytes(&privkey)
                .expect("Can only fail if bytes.len()<32");
            let dalek_pub = ed25519_dalek::PublicKey::from(&dalek_secret);

            let zengo_pub_serialized = &*zengo_keypair.public_key.to_bytes(true);
            let dalek_pub_serialized = dalek_pub.to_bytes();

            assert_eq!(zengo_pub_serialized, dalek_pub_serialized);
        }
    }

    #[test]
    fn test_verify_dalek_signatures() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        println!("test_verify_dalek_signatures seed: {}", now);
        let mut rng = Xoshiro256PlusPlus::seed_from_u64(now as _);

        let mut msg = [0u8; 64];
        let mut privkey = [0u8; 32];
        for msg_len in 0..msg.len() {
            let msg = &mut msg[..msg_len];
            for _ in 0..20 {
                rng.fill_bytes(&mut privkey);
                rng.fill_bytes(msg);
                let dalek_secret = ed25519_dalek::ExpandedSecretKey::from(
                    &ed25519_dalek::SecretKey::from_bytes(&privkey)
                        .expect("Can only fail if bytes.len()<32"),
                );
                let dalek_pub = ed25519_dalek::PublicKey::from(&dalek_secret);
                let dalek_sig = dalek_secret.sign(msg, &dalek_pub);

                let zengo_sig = Signature {
                    R: Point::from_bytes(&dalek_sig.as_ref()[..32]).unwrap(),
                    s: Scalar::from_bytes(&dalek_sig.as_ref()[32..]).unwrap(),
                };
                let zengo_pubkey = Point::from_bytes(&dalek_pub.to_bytes()).unwrap();
                zengo_sig.verify(msg, &zengo_pubkey).unwrap();
            }
        }
    }
}
