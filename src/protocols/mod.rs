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


