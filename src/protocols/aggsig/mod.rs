#![allow(non_snake_case)]
/*
    multi-party-ed25519

    Copyright 2018 by Kzen Networks

    This file is part of multi-party-ed25519 library
    (https://github.com/KZen-networks/multisig-schnorr)

    multi-party-ed25519 is free software: you can redistribute
    it and/or modify it under the terms of the GNU General Public
    License as published by the Free Software Foundation, either
    version 3 of the License, or (at your option) any later version.

    @license GPL-3.0+ <https://github.com/KZen-networks/multi-party-ed25519/blob/master/LICENSE>
*/

//! Simple ed25519
//!
//! See https://tools.ietf.org/html/rfc8032

use super::ExpendedKeyPair;

pub use curv::arithmetic::traits::Samplable;
use curv::cryptographic_primitives::commitments::hash_commitment::HashCommitment;
use curv::cryptographic_primitives::hashing::DigestExt;
use curv::cryptographic_primitives::proofs::*;
use curv::elliptic::curves::{Ed25519, Point, Scalar};
use curv::BigInt;

pub use curv::arithmetic::traits::Converter;
use curv::cryptographic_primitives::commitments::traits::Commitment;
use sha2::{digest::Digest, Sha512};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyAgg {
    pub apk: Point<Ed25519>,
    pub hash: Scalar<Ed25519>,
}

impl KeyAgg {
    pub fn key_aggregation_n(pks: &Vec<Point<Ed25519>>, party_index: &usize) -> KeyAgg {
        let bn_1 = BigInt::from(1);
        let x_coor_vec: Vec<BigInt> = (0..pks.len())
            .into_iter()
            .map(|i| pks[i].y_coord().expect("Should never fail"))
            .collect();
        let hash_vec: Vec<BigInt> = x_coor_vec
            .iter()
            .map(|pk| {
                let mut hasher = Sha512::new();
                hasher.input_bigint(&bn_1);
                hasher.input_bigint(pk);
                for i in 0..pks.len() {
                    hasher.input_bigint(&x_coor_vec[i]);
                }
                hasher.result_bigint()
            })
            .collect();

        let apk_vec: Vec<_> = pks
            .iter()
            .zip(&hash_vec)
            .map(|(pk, hash)| {
                let hash_t = Scalar::from_bigint(hash);
                let a_i = pk * hash_t;
                a_i
            })
            .collect();
        //TODO: remove clones
        let mut apk_vec_2_n = apk_vec.clone();
        let pk1 = apk_vec_2_n.remove(0);
        let sum = apk_vec_2_n.iter().fold(pk1, |acc, pk| acc + pk);

        KeyAgg {
            apk: sum,
            hash: Scalar::from_bigint(&hash_vec[*party_index]),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EphemeralKey {
    pub r: Scalar<Ed25519>,
    pub R: Point<Ed25519>,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct SignFirstMsg {
    pub commitment: BigInt,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct SignSecondMsg {
    pub R: Point<Ed25519>,
    pub blind_factor: BigInt,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Signature {
    pub R: Point<Ed25519>,
    pub s: Scalar<Ed25519>,
}

impl Signature {
    pub fn create_ephemeral_key_and_commit(
        keys: &ExpendedKeyPair,
        message: &[u8],
    ) -> (EphemeralKey, SignFirstMsg, SignSecondMsg) {
        // here we deviate from the spec, by introducing  non-deterministic element (random number)
        // to the nonce
        let r = Sha512::new()
            .chain_bigint(&BigInt::from(2))
            .chain_bigint(&keys.expended_private_key.prefix.to_bigint())
            .chain_bigint(&BigInt::from_bytes(message))
            .chain_bigint(&Scalar::<Ed25519>::random().to_bigint())
            .result_bigint();
        let r = reverse_bn_to_fe(&r);
        let R = Point::generator() * &r;
        let (commitment, blind_factor) =
            HashCommitment::<Sha512>::create_commitment(&R.y_coord().unwrap());
        (
            EphemeralKey { r, R: R.clone() },
            SignFirstMsg { commitment },
            SignSecondMsg { R, blind_factor },
        )
    }
    pub fn k(R_tot: &Point<Ed25519>, apk: &Point<Ed25519>, message: &[u8]) -> Scalar<Ed25519> {
        let k = Sha512::new()
            .chain_point(R_tot)
            .chain_point(apk)
            .chain_bigint(&BigInt::from_bytes(message))
            .result_bigint();
        let k = reverse_bn_to_fe(&k);
        k
    }
    pub fn get_R_tot(mut R: Vec<Point<Ed25519>>) -> Point<Ed25519> {
        let R1 = R.remove(0);
        let sum = R
            .iter()
            .fold(R1, |acc: Point<Ed25519>, Ri: &Point<Ed25519>| acc + Ri);
        sum
    }

    pub fn partial_sign(
        r: &Scalar<Ed25519>,
        keys: &ExpendedKeyPair,
        k: &Scalar<Ed25519>,
        a: &Scalar<Ed25519>,
        R_tot: &Point<Ed25519>,
    ) -> Signature {
        let k_mul_sk = k * &keys.expended_private_key.private_key;
        let k_mul_sk_mul_ai = k_mul_sk * a;
        let s = r + k_mul_sk_mul_ai;
        Signature {
            R: R_tot.clone(),
            s,
        }
    }

    pub fn sign_single(message: &[u8], keys: &ExpendedKeyPair) -> Signature {
        let r = Sha512::new()
            .chain(&*keys.expended_private_key.prefix.to_bytes())
            .chain(message)
            .result_scalar();
        let R = &r * Point::generator();
        let mut k = Sha512::new()
            .chain(&*R.to_bytes(true))
            .chain(&*keys.public_key.to_bytes(true))
            .chain(message)
            .finalize();
        // reverse because BigInt uses BigEndian.
        k.reverse();
        let k = Scalar::from_bigint(&BigInt::from_bytes(&k));

        let k_mul_sk = k * &keys.expended_private_key.private_key;
        let s = r + k_mul_sk;
        Signature { R, s }
    }

    pub fn add_signature_parts(mut sigs: Vec<Signature>) -> Signature {
        //test equality of group elements:
        let candidate_R = &sigs[0].R.clone();
        assert!(sigs.iter().all(|x| &x.R == candidate_R));
        //sum s part of the signature:

        let s1 = sigs.remove(0);
        let sum = sigs
            .iter()
            .fold(s1.s, |acc: Scalar<Ed25519>, si: &Signature| acc + &si.s);
        Signature { s: sum, R: s1.R }
    }
}

pub fn verify(
    signature: &Signature,
    message: &[u8],
    public_key: &Point<Ed25519>,
) -> Result<(), ProofError> {
    let mut k = Sha512::new()
        .chain(&*signature.R.to_bytes(true))
        .chain(&*public_key.to_bytes(true))
        .chain(message)
        .finalize();
    // reverse because BigInt uses BigEndian.
    k.reverse();
    let k = Scalar::from_bigint(&BigInt::from_bytes(&k));

    let A = public_key;

    let kA = A * k;
    let R_plus_kA = kA + &signature.R;
    let sG = &signature.s * Point::generator();

    if R_plus_kA == sG {
        Ok(())
    } else {
        Err(ProofError)
    }
}

pub fn test_com(r_to_test: &Point<Ed25519>, blind_factor: &BigInt, comm: &BigInt) -> bool {
    let computed_comm = &HashCommitment::<Sha512>::create_commitment_with_user_defined_randomness(
        &r_to_test.y_coord().unwrap(),
        blind_factor,
    );
    computed_comm == comm
}
mod test;

pub fn reverse_bn_to_fe(scalar: &BigInt) -> Scalar<Ed25519> {
    let mut vec = BigInt::to_bytes(&scalar);
    vec.reverse();
    let scalar_out = BigInt::from_bytes(&vec[..]);
    Scalar::from_bigint(&scalar_out)
}
