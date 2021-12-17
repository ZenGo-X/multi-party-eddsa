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
//! Schnorr {n,n}-Signatures based on Accountable-Subgroup Multisignatures
//!
//See (https://pdfs.semanticscholar.org/6bf4/f9450e7a8e31c106a8670b961de4735589cf.pdf)

use super::ExpendedKeyPair;

use curv::cryptographic_primitives::hashing::DigestExt;
use curv::elliptic::curves::{Ed25519, Point, Scalar};
use curv::BigInt;
use protocols::multisig;

use sha2::{digest::Digest, Sha512};

// I is a private key and public key keypair, X is a commitment of the form X = xG used only in key generation (see p11 in the paper)
#[derive(Debug, Clone)]
pub struct Keys {
    pub I: ExpendedKeyPair,
    pub X: SingleKeyPair,
}

#[derive(Debug, Clone)]
pub struct SingleKeyPair {
    pub public_key: Point<Ed25519>,
    private_key: Scalar<Ed25519>,
}
impl SingleKeyPair {
    pub fn create() -> SingleKeyPair {
        let ec_point = Point::generator();
        let private_key = Scalar::random();
        let public_key = ec_point * &private_key;
        SingleKeyPair {
            public_key,
            private_key,
        }
    }
    pub fn create_from_private_key(private_key: Scalar<Ed25519>) -> SingleKeyPair {
        let g = Point::generator();
        let public_key = g * &private_key;

        SingleKeyPair {
            public_key,
            private_key,
        }
    }
}

impl ExpendedKeyPair {
    pub fn update_key_pair(&mut self, to_add: Scalar<Ed25519>) {
        self.expended_private_key.private_key = to_add + &self.expended_private_key.private_key;
        let g = Point::generator();
        self.public_key = g * &self.expended_private_key.private_key;
    }
}

impl Keys {
    pub fn create() -> Keys {
        let I = ExpendedKeyPair::create();
        let X = SingleKeyPair::create();
        Keys { I, X }
    }

    pub fn create_from_private_keys(priv_I: [u8; 32], priv_X: Scalar<Ed25519>) -> Keys {
        let I = ExpendedKeyPair::create_from_private_key(priv_I);
        let X = SingleKeyPair::create_from_private_key(priv_X);
        Keys { I, X }
    }

    pub fn create_from(secret_share: [u8; 32]) -> Keys {
        let I = ExpendedKeyPair::create_from_private_key(secret_share);
        let X = SingleKeyPair::create();
        Keys { I, X }
    }

    pub fn create_signing_key(keys: &Keys, eph_key: &EphKey) -> Keys {
        Keys {
            I: keys.I.clone(),
            X: eph_key.eph_key_pair.clone(),
        }
    }

    pub fn broadcast(keys: Keys) -> Vec<Point<Ed25519>> {
        return vec![keys.I.public_key, keys.X.public_key];
    }

    pub fn collect_and_compute_challenge(ix_vec: &[Vec<Point<Ed25519>>]) -> Scalar<Ed25519> {
        let concat_vec = ix_vec.iter().fold(Vec::new(), |mut acc, x| {
            acc.extend_from_slice(x);
            acc
        });
        multisig::hash_4(&concat_vec)
    }
}

pub fn partial_sign(keys: &Keys, e: Scalar<Ed25519>) -> Scalar<Ed25519> {
    e * &keys.I.expended_private_key.private_key + &keys.X.private_key
}

pub fn verify<'a>(I: &Point<Ed25519>, sig: &Signature, e: &Scalar<Ed25519>) -> Result<(), &'a str> {
    let X = &sig.X;
    let y = &sig.y;
    let base_point = Point::generator();
    let yG = base_point * y;
    let eI = I * e;
    let X_plus_eI = X + &eI;
    if yG == X_plus_eI {
        Ok(())
    } else {
        Err("error verification")
    }
}

fn hash_4(key_list: &[Point<Ed25519>]) -> Scalar<Ed25519> {
    let four_fe: Scalar<Ed25519> = Scalar::from_bigint(&BigInt::from(4));
    let base_point = Point::generator();
    let four_ge = base_point * four_fe;
    Sha512::new()
        .chain_point(&four_ge)
        .chain_points(key_list)
        .result_scalar()
}

pub struct EphKey {
    pub eph_key_pair: SingleKeyPair,
}

impl EphKey {
    //signing step 1
    pub fn gen_commit(key_gen_key_pair: &ExpendedKeyPair, message: &BigInt) -> EphKey {
        // here we deviate from the spec, by introducing  non-deterministic element (random number)
        // to the nonce
        let r = Sha512::new()
            .chain_scalar(&key_gen_key_pair.expended_private_key.prefix)
            .chain_bigint(message)
            .chain_scalar(&Scalar::<Ed25519>::random())
            .result_bigint();
        let r_fe = Scalar::from_bigint(&r);
        let g = Point::generator();
        let eph_key_pair = SingleKeyPair {
            public_key: g * &r_fe,
            private_key: r_fe,
        };
        EphKey { eph_key_pair }
    }
    //signing steps 2,3
    // we treat S as a list of public keys and compute a sum.
    pub fn compute_joint_comm_e(
        mut pub_key_vec: Vec<Point<Ed25519>>,
        mut eph_pub_key_vec: Vec<Point<Ed25519>>,
        message: &BigInt,
    ) -> (Point<Ed25519>, Point<Ed25519>, Scalar<Ed25519>) {
        let first_pub_key = pub_key_vec.remove(0);
        let sum_pub = pub_key_vec.iter().fold(first_pub_key, |acc, x| acc + x);
        let first_eph_pub_key = eph_pub_key_vec.remove(0);
        let sum_pub_eph = eph_pub_key_vec
            .iter()
            .fold(first_eph_pub_key, |acc, x| acc + x);
        //TODO: maybe there is a better way?
        let m_fe = Scalar::from_bigint(message);
        let base_point = Point::generator();
        let m_ge = base_point * m_fe;
        let e = multisig::hash_4(&[sum_pub_eph.clone(), m_ge, sum_pub.clone()]);
        (sum_pub, sum_pub_eph, e)
    }

    pub fn partial_sign(
        &self,
        local_keys: &ExpendedKeyPair,
        es: Scalar<Ed25519>,
    ) -> Scalar<Ed25519> {
        es * &local_keys.expended_private_key.private_key + &self.eph_key_pair.private_key
    }

    pub fn add_signature_parts(sig_vec: Vec<Scalar<Ed25519>>) -> Scalar<Ed25519> {
        let mut sig_vec_c = sig_vec;
        let first_sig = sig_vec_c.remove(0);

        sig_vec_c.iter().fold(first_sig, |acc, x| acc + x)
    }
}

pub struct Signature {
    X: Point<Ed25519>,
    y: Scalar<Ed25519>,
}

impl Signature {
    pub fn set_signature(X: &Point<Ed25519>, y: &Scalar<Ed25519>) -> Signature {
        Signature {
            X: X.clone(),
            y: y.clone(),
        }
    }
}

mod test;
