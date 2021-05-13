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
use curv::cryptographic_primitives::proofs::*;
pub use curv::elliptic::curves::traits::*;
use curv::elliptic::curves::ed25519::{GE, FE};
use curv::BigInt;

use curv::cryptographic_primitives::hashing::hash_sha512::HSha512;
use curv::cryptographic_primitives::hashing::traits::*;

pub use curv::arithmetic::traits::Converter;
use curv::cryptographic_primitives::commitments::hash_commitment::HashCommitment;
use curv::cryptographic_primitives::commitments::traits::*;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExpendedPrivateKey {
    pub prefix: FE,
    private_key: FE,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyAgg {
    pub apk: GE,
    pub hash: FE,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyPair {
    pub public_key: GE,
    expended_private_key: ExpendedPrivateKey,
}

impl KeyPair {
    pub fn create() -> KeyPair {
        let sk: FE = ECScalar::new_random();
        Self::create_from_private_key_internal(&sk)
    }

    pub fn create_from_private_key(secret: &BigInt) -> KeyPair {
        let sk: FE = ECScalar::from(secret);
        Self::create_from_private_key_internal(&sk)
    }

    fn create_from_private_key_internal(sk: &FE) -> KeyPair {
        let ec_point: GE = ECPoint::generator();
        let h = HSha512::create_hash(&vec![&sk.to_big_int()]);
        let h_vec = BigInt::to_bytes(&h);
        let mut h_vec_padded = vec![0; 64 - h_vec.len()];  // ensure hash result is padded to 64 bytes
        h_vec_padded.extend_from_slice(&h_vec);
        let mut private_key: [u8; 32] = [0u8; 32];
        let mut prefix: [u8; 32] = [0u8; 32];
        prefix.copy_from_slice(&h_vec_padded[32..64]);
        private_key.copy_from_slice(&h_vec_padded[00..32]);
        private_key[0] &= 248;
        private_key[31] &= 63;
        private_key[31] |= 64;
        let private_key = &private_key[..private_key.len()];
        let prefix = &prefix[..prefix.len()];
        let private_key: FE = ECScalar::from(&BigInt::from_bytes(private_key));
        let prefix: FE = ECScalar::from(&BigInt::from_bytes(prefix));
        let public_key = ec_point * &private_key;
        KeyPair {
            public_key,
            expended_private_key: ExpendedPrivateKey {
                prefix,
                private_key,
            },
        }
    }

    pub fn key_aggregation_n(pks: &Vec<GE>, party_index: &usize) -> KeyAgg {
        let bn_1 = BigInt::from(1);
        let x_coor_vec: Vec<BigInt> = (0..pks.len())
            .into_iter()
            .map(|i| pks[i].bytes_compressed_to_big_int())
            .collect();
        let hash_vec: Vec<BigInt> = x_coor_vec
            .iter()
            .map(|pk| {
                let mut vec = Vec::new();
                vec.push(&bn_1);
                vec.push(pk);
                for i in 0..pks.len() {
                    vec.push(&x_coor_vec[i]);
                }
                HSha512::create_hash(&vec)
            })
            .collect();

        let apk_vec: Vec<GE> = pks
            .iter()
            .zip(&hash_vec)
            .map(|(pk, hash)| {
                let hash_t: FE = ECScalar::from(&hash);
                let pki: GE = pk.clone();
                let a_i = pki * &hash_t;
                a_i
            })
            .collect();
        //TODO: remove clones
        let mut apk_vec_2_n = apk_vec.clone();
        let pk1 = apk_vec_2_n.remove(0);
        let sum = apk_vec_2_n.iter().fold(pk1, |acc, pk| acc + pk);

        KeyAgg {
            apk: sum,
            hash: ECScalar::from(&hash_vec[*party_index].clone()),
        }
    }
}
#[derive(Debug, Serialize, Deserialize)]
pub struct EphemeralKey {
    pub r: FE,
    pub R: GE,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct SignFirstMsg {
    pub commitment: BigInt,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct SignSecondMsg {
    pub R: GE,
    pub blind_factor: BigInt,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Signature {
    pub R: GE,
    pub s: FE,
}

impl Signature {
    pub fn create_ephemeral_key_and_commit(
        keys: &KeyPair,
        message: &[u8],
    ) -> (EphemeralKey, SignFirstMsg, SignSecondMsg) {
        // here we deviate from the spec, by introducing  non-deterministic element (random number)
        // to the nonce
        let r = HSha512::create_hash(&vec![
            &BigInt::from(2), // domain seperation
            &keys.expended_private_key.prefix.to_big_int(),
            &BigInt::from_bytes(message),
            &FE::new_random().to_big_int(),
        ]);
        let r = reverse_bn_to_fe(&r);
        let ec_point: GE = ECPoint::generator();
        let R: GE = ec_point * &r;
        let (commitment, blind_factor) =
            HashCommitment::create_commitment(&R.bytes_compressed_to_big_int());
        (
            EphemeralKey { r, R: R.clone() },
            SignFirstMsg { commitment },
            SignSecondMsg { R, blind_factor },
        )
    }
    pub fn k(R_tot: &GE, apk: &GE, message: &[u8]) -> FE {
        let k = HSha512::create_hash(&vec![
            &R_tot.bytes_compressed_to_big_int(),
            &apk.bytes_compressed_to_big_int(),
            &BigInt::from_bytes(message),
        ]);
        let k = reverse_bn_to_fe(&k);
        k
    }
    pub fn get_R_tot(mut R: Vec<GE>) -> GE {
        let R1 = R.remove(0);
        let sum = R.iter().fold(R1, |acc: GE, Ri: &GE| acc + Ri);
        sum
    }

    pub fn partial_sign(r: &FE, keys: &KeyPair, k: &FE, a: &FE, R_tot: &GE) -> Signature {
        let k_mul_sk = k.mul(&keys.expended_private_key.private_key.get_element());
        let k_mul_sk_mul_ai = k_mul_sk.mul(&a.get_element());
        let s = r.add(&k_mul_sk_mul_ai.get_element());
        Signature {
            R: R_tot.clone(),
            s,
        }
    }

    pub fn sign_single(message: &[u8], keys: &KeyPair) -> Signature {
        let r = HSha512::create_hash(&vec![
            &keys.expended_private_key.prefix.to_big_int(),
            &BigInt::from_bytes(message),
        ]);
        let r: FE = ECScalar::from(&r);
        let ec_point: GE = ECPoint::generator();
        let R = ec_point.scalar_mul(&r.get_element());
        let k = HSha512::create_hash(&vec![
            &R.bytes_compressed_to_big_int(),
            &keys.public_key.bytes_compressed_to_big_int(),
            &BigInt::from_bytes(message),
        ]);
        let k = reverse_bn_to_fe(&k);
        let k_mul_sk = k.mul(&keys.expended_private_key.private_key.get_element());
        let s = r.add(&k_mul_sk.get_element());
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
            .fold(s1.s, |acc: FE, si: &Signature| acc.add(&si.s.get_element()));
        Signature { s: sum, R: s1.R }
    }
}

pub fn verify(signature: &Signature, message: &[u8], public_key: &GE) -> Result<(), ProofError> {
    let k = HSha512::create_hash(&vec![
        &signature.R.bytes_compressed_to_big_int(),
        &public_key.bytes_compressed_to_big_int(),
        &BigInt::from_bytes(message),
    ]);

    let k_fe = reverse_bn_to_fe(&k);

    let base_point: GE = ECPoint::generator();

    let A: GE = public_key.clone();
    let kA = A * k_fe;
    let sG = base_point * &signature.s;
    let R_plus_kA = kA + &(signature.R);

    if R_plus_kA == sG {
        Ok(())
    } else {
        Err(ProofError)
    }
}

pub fn test_com(r_to_test: &GE, blind_factor: &BigInt, comm: &BigInt) -> bool {
    let computed_comm = &HashCommitment::create_commitment_with_user_defined_randomness(
        &r_to_test.bytes_compressed_to_big_int(),
        blind_factor,
    );
    computed_comm == comm
}
mod test;

pub fn reverse_bn_to_fe(scalar: &BigInt) -> FE {
    let mut vec = BigInt::to_bytes(&scalar);
    vec.reverse();
    let scalar_out = BigInt::from_bytes(&vec[..]);
    ECScalar::from(&scalar_out)
}
