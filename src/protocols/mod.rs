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
pub mod musig2;
pub mod thresholdsig;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExpandedPrivateKey {
    pub prefix: Scalar<Ed25519>,
    pub private_key: Scalar<Ed25519>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExpandedKeyPair {
    pub public_key: Point<Ed25519>,
    pub expanded_private_key: ExpandedPrivateKey,
}

impl ExpandedKeyPair {
    pub fn create() -> ExpandedKeyPair {
        let secret = thread_rng().gen();
        Self::create_from_private_key(secret)
    }

    pub fn create_from_private_key(secret: [u8; 32]) -> ExpandedKeyPair {
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
        let prefix =
            Scalar::from_bytes(&prefix).expect("prefix is the right length, so can't fail");
        let public_key = Point::generator() * &private_key;
        ExpandedKeyPair {
            public_key,
            expanded_private_key: ExpandedPrivateKey {
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
        let R_plus_kA = &kA + &self.R;
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
        // This will reduce it mod the group order.
        Scalar::from_bigint(&BigInt::from_bytes(&k))
    }
}

#[cfg(test)]
pub(crate) mod tests {

    use curv::elliptic::curves::{Ed25519, Point, Scalar};
    use ed25519_dalek::Verifier;
    use rand::{thread_rng, Rng};
    use rand_xoshiro::rand_core::{RngCore, SeedableRng};
    use rand_xoshiro::Xoshiro256PlusPlus;

    use protocols::{ExpandedKeyPair, Signature};

    pub fn verify_dalek(pk: &Point<Ed25519>, sig: &Signature, msg: &[u8]) -> bool {
        let mut sig_bytes = [0u8; 64];
        sig_bytes[..32].copy_from_slice(&*sig.R.to_bytes(true));
        sig_bytes[32..].copy_from_slice(&sig.s.to_bytes());

        let dalek_pub = ed25519_dalek::PublicKey::from_bytes(&*pk.to_bytes(true)).unwrap();
        let dalek_sig = ed25519_dalek::Signature::from_bytes(&sig_bytes).unwrap();

        dalek_pub.verify(msg, &dalek_sig).is_ok()
    }

    /// This will generate a fast deterministic rng and will print the seed,
    /// if a test fails, pass in the printed seed to reproduce.
    pub fn deterministic_fast_rand(name: &str, seed: Option<u64>) -> impl Rng {
        let seed = seed.unwrap_or_else(|| thread_rng().gen());
        println!("{} seed: {}", name, seed);
        Xoshiro256PlusPlus::seed_from_u64(seed)
    }

    #[test]
    fn test_generate_pubkey_dalek() {
        let mut rng = deterministic_fast_rand("test_generate_pubkey_dalek", None);

        let mut privkey = [0u8; 32];
        for _ in 0..4096 {
            rng.fill_bytes(&mut privkey);
            let zengo_keypair = ExpandedKeyPair::create_from_private_key(privkey);
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
        let mut rng = deterministic_fast_rand("test_verify_dalek_signatures", None);

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
