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
use curv::elliptic::curves::{Ed25519, Point, Scalar};
use curv::BigInt;

pub use curv::arithmetic::traits::Converter;
use curv::cryptographic_primitives::commitments::traits::Commitment;
use protocols::{ProofError, Signature};
use rand::{thread_rng, Rng};
use sha2::{digest::Digest, Sha512};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyAgg {
    pub apk: Point<Ed25519>,
    pub hash: Scalar<Ed25519>,
}

impl KeyAgg {
    pub fn key_aggregation_n(pks: &[Point<Ed25519>], party_index: usize) -> KeyAgg {
        let mut my_hash = Scalar::zero();
        let mut sum = Point::zero();
        pks.iter().enumerate().for_each(|(index, pk)| {
            let mut hasher = Sha512::new().chain(&[1]).chain(&*pk.to_bytes(true));
            for pk in pks {
                hasher.update(&*pk.to_bytes(true));
            }
            let hash = hasher.result_scalar();
            let a_i = pk * &hash;
            if index == party_index {
                my_hash = hash;
            }
            sum = &sum + a_i
        });

        KeyAgg {
            apk: sum,
            hash: my_hash,
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

pub fn create_ephemeral_key_and_commit(
    keys: &ExpendedKeyPair,
    message: &[u8],
) -> (EphemeralKey, SignFirstMsg, SignSecondMsg) {
    create_ephemeral_key_and_commit_rng(keys, message, &mut thread_rng())
}

fn create_ephemeral_key_and_commit_rng(
    keys: &ExpendedKeyPair,
    message: &[u8],
    rng: &mut impl Rng,
) -> (EphemeralKey, SignFirstMsg, SignSecondMsg) {
    // here we deviate from the spec, by introducing  non-deterministic element (random number)
    // to the nonce
    let r = Sha512::new()
        .chain(&[2])
        .chain(&*keys.expended_private_key.prefix.to_bytes())
        .chain(message)
        .chain(rng.gen::<[u8; 32]>())
        .result_scalar();
    let R = Point::generator() * &r;
    let (commitment, blind_factor) =
        HashCommitment::<Sha512>::create_commitment(&R.y_coord().unwrap());
    (
        EphemeralKey { r, R: R.clone() },
        SignFirstMsg { commitment },
        SignSecondMsg { R, blind_factor },
    )
}
pub fn get_R_tot(Rs: &[Point<Ed25519>]) -> Point<Ed25519> {
    let first = Rs[0].clone();
    Rs[1..].iter().fold(first, |acc, Ri| acc + Ri)
}

pub fn partial_sign(
    r: &Scalar<Ed25519>,
    keys: &ExpendedKeyPair,
    a: &Scalar<Ed25519>,
    R_tot: &Point<Ed25519>,
    agg_pubkey: &Point<Ed25519>,
    msg: &[u8],
) -> Signature {
    let k = Signature::k(R_tot, agg_pubkey, msg);
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
    let k = Signature::k(&R, &keys.public_key, message);

    let k_mul_sk = k * &keys.expended_private_key.private_key;
    let s = r + k_mul_sk;
    Signature { R, s }
}

pub fn add_signature_parts(sigs: &[Signature]) -> Signature {
    //test equality of group elements:
    assert!(sigs[1..].iter().all(|x| x.R == sigs[0].R));
    //sum s part of the signature:

    let s1 = sigs[0].s.clone();
    let sum = sigs[1..].iter().fold(s1, |acc, si| acc + &si.s);
    Signature {
        s: sum,
        R: sigs[0].R.clone(),
    }
}

pub fn verify_partial_sig(
    sig: &Signature,
    message: &[u8],
    a: &Scalar<Ed25519>,
    partial_R: &Point<Ed25519>,
    partial_public_key: &Point<Ed25519>,
    agg_pubkey: &Point<Ed25519>,
) -> Result<(), ProofError> {
    let k = Signature::k(&sig.R, agg_pubkey, message);
    let A = partial_public_key;

    let kA = A * k * a;

    let R_plus_kA = kA + partial_R;
    let sG = &sig.s * Point::generator();

    if R_plus_kA == sG {
        Ok(())
    } else {
        Err(ProofError)
    }
}

mod test;
