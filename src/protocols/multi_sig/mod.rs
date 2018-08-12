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

//! Simple ed25519
//!
//! See https://tools.ietf.org/html/rfc8032
use cryptography_utils::{BigInt, FE, GE, PK, SK};

use cryptography_utils::cryptographic_primitives::proofs::*;
use cryptography_utils::elliptic::curves::traits::*;

use cryptography_utils::cryptographic_primitives::hashing::hash_sha512::HSha512;
use cryptography_utils::cryptographic_primitives::hashing::traits::*;

use cryptography_utils::arithmetic::traits::Converter;
use cryptography_utils::arithmetic::traits::Modulo;
use cryptography_utils::cryptographic_primitives::commitments::hash_commitment::HashCommitment;
use cryptography_utils::cryptographic_primitives::commitments::traits::*;

#[derive(Debug)]
pub struct ExpendedPrivateKey {
    pub prefix: FE,
    private_key: FE,
}

pub struct KeyPair {
    pub public_key: GE,
    expended_private_key: ExpendedPrivateKey,
}

impl KeyPair {
    pub fn create() -> KeyPair {
        let ec_point: GE = ECPoint::new();
        let mut hash: [u8; 64] = [0u8; 64];
        let sk: FE = ECScalar::new_random();
        let h = HSha512::create_hash(vec![&sk.to_big_int()]);
        let h_vec = BigInt::to_vec(&h);
        let mut private_key: [u8; 32] = [0u8; 32];
        let mut prefix: [u8; 32] = [0u8; 32];
        prefix.copy_from_slice(&h_vec[32..64]);
        private_key.copy_from_slice(&h_vec[00..32]);
        private_key[0] &= 248;
        private_key[31] &= 63;
        private_key[31] |= 64;
        let private_key = &private_key[..private_key.len()];
        let prefix = &prefix[..prefix.len()];
        let private_key: FE = ECScalar::from_big_int(&BigInt::from(private_key));
        let prefix: FE = ECScalar::from_big_int(&BigInt::from(prefix));
        let public_key = ec_point.scalar_mul(&private_key.get_element());
        KeyPair {
            public_key,
            expended_private_key: ExpendedPrivateKey {
                prefix,
                private_key,
            },
        }
    }

    pub fn create_from_private_key(secret: &BigInt) -> KeyPair {
        let sk: FE = ECScalar::from_big_int(secret);
        let ec_point: GE = ECPoint::new();
        let mut hash: [u8; 64] = [0u8; 64];
        let sk: FE = ECScalar::new_random();
        let h = HSha512::create_hash(vec![&sk.to_big_int()]);
        let h_vec = BigInt::to_vec(&h);
        let mut private_key: [u8; 32] = [0u8; 32];
        let mut prefix: [u8; 32] = [0u8; 32];
        prefix.copy_from_slice(&h_vec[32..64]);
        private_key.copy_from_slice(&h_vec[00..32]);
        private_key[0] &= 248;
        private_key[31] &= 63;
        private_key[31] |= 64;
        let private_key = &private_key[..private_key.len()];
        let prefix = &prefix[..prefix.len()];
        let private_key: FE = ECScalar::from_big_int(&BigInt::from(private_key));
        let prefix: FE = ECScalar::from_big_int(&BigInt::from(prefix));
        let public_key = ec_point.scalar_mul(&private_key.get_element());
        KeyPair {
            public_key,
            expended_private_key: ExpendedPrivateKey {
                prefix,
                private_key,
            },
        }
    }
}

#[derive(Debug)]
pub struct Signature {
    pub R: GE,
    pub s: FE,
}

impl Signature {
    pub fn sign(message: &[u8], keys: &KeyPair) -> Signature {
        let temps: FE = ECScalar::new_random();
        let curve_order = temps.get_q();
        let r = HSha512::create_hash(vec![
            &keys.expended_private_key.prefix.to_big_int(),
            &BigInt::from(message),
        ]);
        let r: FE = ECScalar::from_big_int(&r);
        let ec_point: GE = ECPoint::new();
        let R = ec_point.scalar_mul(&r.get_element());
        let k = HSha512::create_hash(vec![
            &R.bytes_compressed_to_big_int(),
            &keys.public_key.bytes_compressed_to_big_int(),
            &BigInt::from(message),
        ]);
        let k: FE = ECScalar::from_big_int(&k);
        let k_mul_sk = k.mul(&keys.expended_private_key.private_key.get_element());
        let s = r.add(&k_mul_sk.get_element());
        Signature { R, s }
    }
}

pub fn verify(signature: &Signature, message: &[u8], public_key: &GE) -> Result<(), ProofError> {
    let k = HSha512::create_hash(vec![
        &signature.R.bytes_compressed_to_big_int(),
        &public_key.bytes_compressed_to_big_int(),
        &BigInt::from(message),
    ]);

    let base_point: GE = ECPoint::new();
    let temps: FE = ECScalar::new_random();
    let curve_order = temps.get_q();
    //let curve_order_fe: FE = ECScalar::from_big_int(&curve_order);
    let k_fe: FE = ECScalar::from_big_int(&k);
    //let minus_k_fe = curve_order_fe.sub(&k_fe.get_element());
    let mut A: GE = public_key.clone();
    let kA = A.scalar_mul(&k_fe.get_element());
    let sG = base_point.scalar_mul(&signature.s.get_element());
    let R_plus_kA = signature.R.add_point(&kA.get_element());
    if R_plus_kA.get_element() == sG.get_element() {
        Ok(())
    } else {
        Err(ProofError)
    }
}

mod test;
