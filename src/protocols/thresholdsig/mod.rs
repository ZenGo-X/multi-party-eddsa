#![allow(non_snake_case)]
/*
    Multisig eddsa
    Copyright 2018 by Kzen Networks
    This file is part of multi-party-eddsa library
    (https://github.com/KZen-networks/multi-party-eddsa)
    Multisig Schnorr is free software: you can redistribute
    it and/or modify it under the terms of the GNU General Public
    License as published by the Free Software Foundation, either
    version 3 of the License, or (at your option) any later version.
    @license GPL-3.0+ <https://github.com/KZen-networks/multi-party-eddsa/blob/master/LICENSE>
*/
use crate::Error::{self, InvalidKey, InvalidSS};

use curv::arithmetic::traits::*;
use curv::cryptographic_primitives::commitments::hash_commitment::HashCommitment;
use curv::cryptographic_primitives::commitments::traits::Commitment;
use curv::cryptographic_primitives::hashing::DigestExt;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::{SecretShares, VerifiableSS};
use curv::elliptic::curves::{Ed25519, Point, Scalar};
use curv::BigInt;
use crate::protocols::{ExpendedKeyPair, FE, GE, Signature};
use rand::{thread_rng, Rng};
use sha2::{digest::Digest, Sha512};

const SECURITY: usize = 256;

// u_i is private key and {u__i, prefix} are extended private key.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Keys {
    pub keypair: ExpendedKeyPair,
    pub party_index: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyGenBroadcastMessage1 {
    com: BigInt,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyGenDecommitMessage1 {
    pub blind_factor: BigInt,
    pub y_i: GE,
}

#[derive(Debug)]
pub struct Parameters {
    pub threshold: u16,   //t
    pub share_count: u16, //n
}
#[derive(Clone, Serialize, Deserialize)]
pub struct SharedKeys {
    pub y: GE,
    pub x_i: FE,
    pub prefix: FE,
}

pub struct EphemeralKey {
    pub r_i: Scalar<Ed25519>,
    pub R_i: Point<Ed25519>,
    pub party_index: u16,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct EphemeralSharedKeys {
    pub R: Point<Ed25519>,
    pub r_i: Scalar<Ed25519>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct LocalSig {
    gamma_i: Scalar<Ed25519>,
    k: Scalar<Ed25519>,
}

impl Keys {
    pub fn phase1_create(party_index: u16) -> Keys {
        Keys {
            keypair: ExpendedKeyPair::create(),
            party_index,
        }
    }

    pub fn phase1_create_from_private_key(party_index: u16, secret: [u8; 32]) -> Keys {
        Keys {
            keypair: ExpendedKeyPair::create_from_private_key(secret),
            party_index,
        }
    }

    pub fn phase1_broadcast(&self) -> (KeyGenBroadcastMessage1, KeyGenDecommitMessage1) {
        self.phase1_broadcast_rng(&mut thread_rng())
    }

    fn phase1_broadcast_rng(&self, rng: &mut impl Rng) -> (KeyGenBroadcastMessage1, KeyGenDecommitMessage1) {
        let blind_factor: [u8; SECURITY / 8] = rng.gen();
        let blind_factor = BigInt::from_bytes(&blind_factor);
        let com = HashCommitment::<Sha512>::create_commitment_with_user_defined_randomness(
            &self.keypair.public_key.y_coord().unwrap(),
            &blind_factor,
        );
        let bcm1 = KeyGenBroadcastMessage1 { com };
        (bcm1, KeyGenDecommitMessage1 {
            blind_factor,
            y_i: self.keypair.public_key.clone()
        })
    }

    pub fn phase1_verify_com_phase2_distribute(
        &self,
        params: &Parameters,
        blind_vec: &[BigInt],
        y_vec: &[Point<Ed25519>],
        bc1_vec: &[KeyGenBroadcastMessage1],
        parties: &[u16],
    ) -> Result<(VerifiableSS<Ed25519>, SecretShares<Ed25519>), Error> {
        // test length:
        assert_eq!(blind_vec.len(), usize::from(params.share_count));
        assert_eq!(bc1_vec.len(), usize::from(params.share_count));
        assert_eq!(y_vec.len(), usize::from(params.share_count));
        // test decommitments
        let correct_key_correct_decom_all = y_vec
            .iter()
            .zip(blind_vec.iter())
            .zip(bc1_vec.iter())
            .all(|((y, blind), comm)| {
                HashCommitment::<Sha512>::create_commitment_with_user_defined_randomness(
                    &y.y_coord().unwrap(),
                    blind,
                ) == comm.com
            });
        if !correct_key_correct_decom_all {
            return Err(InvalidKey);
        }
        
        Ok(VerifiableSS::<Ed25519>::share_at_indices(
            params.threshold,
            params.share_count,
            &self.keypair.expended_private_key.private_key,
            parties,
        ))
    }

    pub fn phase2_verify_vss_construct_keypair(
        &self,
        params: &Parameters,
        y_vec: &[Point<Ed25519>],
        secret_shares_vec: &[Scalar<Ed25519>],
        vss_scheme_vec: &[VerifiableSS<Ed25519>],
        index: u16,
    ) -> Result<SharedKeys, Error> {
        assert_eq!(y_vec.len(), usize::from(params.share_count));
        assert_eq!(secret_shares_vec.len(), usize::from(params.share_count));
        assert_eq!(vss_scheme_vec.len(), usize::from(params.share_count));

        let correct_ss_verify = vss_scheme_vec
            .iter()
            .zip(secret_shares_vec.iter())
            .zip(y_vec.iter())
            .all(|((vss_scheme, secret_share), y)| {
                vss_scheme.validate_share(secret_share, index).is_ok()
                    && &vss_scheme.commitments[0] == y
            });
        if !correct_ss_verify {
            return Err(InvalidSS);
        }
        let first_y = y_vec[0].clone();
        let y = y_vec[1..].iter().fold(first_y, |acc, y| acc + y);
        let x_i = secret_shares_vec
            .iter()
            .fold(Scalar::zero(), |acc, x| acc + x);
        Ok(SharedKeys {
            y,
            x_i,
            prefix: self.keypair.expended_private_key.prefix.clone(),
        })
    }
}

impl EphemeralKey {
    // r = H(prefix||M): in order to do it for global r we need MPC. we skip it and deviate from the protocol
    // Nevertheless our ephemeral key will still be deterministic as a sum of deterministic ephemeral keys:

    pub fn ephermeral_key_create_from_deterministic_secret(
        keys: &Keys,
        message: &[u8],
        index: u16,
    ) -> EphemeralKey {
        Self::ephermeral_key_create_from_deterministic_secret_rng(
            keys,
            message,
            index,
            &mut thread_rng(),
        )
    }

    fn ephermeral_key_create_from_deterministic_secret_rng(
        keys: &Keys,
        message: &[u8],
        index: u16,
        rng: &mut impl Rng,
    ) -> EphemeralKey {
        // here we deviate from the spec, by introducing  non-deterministic element (random number)
        // to the nonce
        let r_i = Sha512::new()
            .chain_scalar(&keys.keypair.expended_private_key.prefix)
            .chain(message)
            .chain(rng.gen::<[u8; 32]>())
            .result_scalar();
        let R_i = Point::generator() * &r_i;

        EphemeralKey {
            r_i,
            R_i,
            party_index: index,
        }
    }

    pub fn phase1_broadcast(&self) -> (KeyGenBroadcastMessage1, BigInt) {
        self.phase1_broadcast_rng(&mut thread_rng())
    }

    pub fn phase1_broadcast_rng(&self, rng: &mut impl Rng) -> (KeyGenBroadcastMessage1, BigInt) {
        let blind_factor: [u8; SECURITY / 8] = rng.gen();
        let blind_factor = BigInt::from_bytes(&blind_factor);
        let com = HashCommitment::<Sha512>::create_commitment_with_user_defined_randomness(
            &self.R_i.y_coord().unwrap(),
            &blind_factor,
        );
        let bcm1 = KeyGenBroadcastMessage1 { com };
        (bcm1, blind_factor)
    }

    pub fn phase1_verify_com_phase2_distribute(
        &self,
        params: &Parameters,
        blind_vec: &[BigInt],
        R_vec: &[Point<Ed25519>],
        bc1_vec: &[KeyGenBroadcastMessage1],
        parties: &[u16],
    ) -> Result<(VerifiableSS<Ed25519>, SecretShares<Ed25519>), Error> {
        // test length:
        assert!(
            blind_vec.len() > usize::from(params.threshold)
                && blind_vec.len() <= usize::from(params.share_count)
        );
        assert!(
            bc1_vec.len() > usize::from(params.threshold)
                && bc1_vec.len() <= usize::from(params.share_count)
        );
        assert!(
            R_vec.len() > usize::from(params.threshold)
                && R_vec.len() <= usize::from(params.share_count)
        );
        // test decommitments
        let correct_key_correct_decom_all = R_vec
            .iter()
            .zip(blind_vec.iter())
            .zip(bc1_vec.iter())
            .all(|((R, blind), comm)| {
                HashCommitment::<Sha512>::create_commitment_with_user_defined_randomness(
                    &R.y_coord().unwrap(),
                    blind,
                ) == comm.com
            });

        if !correct_key_correct_decom_all {
            return Err(InvalidKey);
        }

        Ok(VerifiableSS::share_at_indices(
            params.threshold,
            params.share_count,
            &self.r_i,
            parties,
        ))
    }

    pub fn phase2_verify_vss_construct_keypair(
        &self,
        params: &Parameters,
        R_vec: &[Point<Ed25519>],
        secret_shares_vec: &[Scalar<Ed25519>],
        vss_scheme_vec: &[VerifiableSS<Ed25519>],
        index: u16,
    ) -> Result<EphemeralSharedKeys, Error> {
        assert!(
            R_vec.len() > usize::from(params.threshold)
                && R_vec.len() <= usize::from(params.share_count)
        );
        assert!(
            secret_shares_vec.len() > usize::from(params.threshold)
                && secret_shares_vec.len() <= usize::from(params.share_count)
        );
        assert!(
            vss_scheme_vec.len() > usize::from(params.threshold)
                && vss_scheme_vec.len() <= usize::from(params.share_count)
        );

        let correct_ss_verify = vss_scheme_vec
            .iter()
            .zip(secret_shares_vec.iter())
            .zip(R_vec.iter())
            .all(|((vss_scheme, secret_share), R)| {
                vss_scheme.validate_share(secret_share, index).is_ok()
                    && &vss_scheme.commitments[0] == R
            });
        if !correct_ss_verify {
            return Err(InvalidSS);
        }

        let R_first = R_vec[0].clone();
        let R = R_vec[1..].iter().fold(R_first, |acc, x| acc + x);
        let r_i = secret_shares_vec
            .iter()
            .fold(Scalar::zero(), |acc, x| acc + x);
        Ok(EphemeralSharedKeys { R, r_i })
    }
}

impl LocalSig {
    pub fn compute(
        message: &[u8],
        local_ephemaral_key: &EphemeralSharedKeys,
        local_private_key: &SharedKeys,
    ) -> LocalSig {
        let r_i = local_ephemaral_key.r_i.clone();
        let s_i = local_private_key.x_i.clone();

        let k = Signature::k(&local_ephemaral_key.R, &local_private_key.y, message);
        let gamma_i = r_i + &k * s_i;

        LocalSig { gamma_i, k }
    }

    // section 4.2 step 3
    #[allow(unused_doc_comments)]
    pub fn verify_local_sigs(
        gamma_vec: &[LocalSig],
        parties_index_vec: &[u16],
        vss_private_keys: &[VerifiableSS<Ed25519>],
        vss_ephemeral_keys: &[VerifiableSS<Ed25519>],
    ) -> Result<VerifiableSS<Ed25519>, Error> {
        //parties_index_vec is a vector with indices of the parties that are participating and provided gamma_i for this step
        // test that enough parties are in this round
        assert!(parties_index_vec.len() > usize::from(vss_private_keys[0].parameters.threshold));

        // Vec of joint commitments:
        // n' = num of signers, n - num of parties in keygen
        // [com0_eph_0,... ,com0_eph_n', e*com0_kg_0, ..., e*com0_kg_n ;
        // ...  ;
        // comt_eph_0,... ,comt_eph_n', e*comt_kg_0, ..., e*comt_kg_n ]
        let comm_vec: Vec<_> = (0..usize::from(vss_private_keys[0].parameters.threshold) + 1)
            .map(|i| {
                let mut key_gen_comm_i_vec: Vec<_> = (0..vss_private_keys.len())
                    .map(|j| &vss_private_keys[j].commitments[i] * &gamma_vec[i].k)
                    .collect();
                let mut eph_comm_i_vec: Vec<_> = (0..vss_ephemeral_keys.len())
                    .map(|j| vss_ephemeral_keys[j].commitments[i].clone())
                    .collect();
                key_gen_comm_i_vec.append(&mut eph_comm_i_vec);
                let first = key_gen_comm_i_vec[0].clone();
                key_gen_comm_i_vec[1..].iter().fold(first, |acc, x| acc + x)
            })
            .collect();

        let vss_sum = VerifiableSS {
            parameters: vss_ephemeral_keys[0].parameters.clone(),
            commitments: comm_vec,
        };

        let g = Point::generator();

        let correct_ss_verify =
            gamma_vec
                .iter()
                .zip(parties_index_vec.iter())
                .all(|(gamma, &party_index)| {
                    let gamma_i_g = &gamma.gamma_i * g;
                    vss_sum
                        .validate_share_public(&gamma_i_g, party_index + 1)
                        .is_ok()
                });

        match correct_ss_verify {
            true => Ok(vss_sum),
            false => Err(InvalidSS),
        }
    }
}

pub fn generate(
    vss_sum_local_sigs: &VerifiableSS<Ed25519>,
    local_sig_vec: &[LocalSig],
    parties_index_vec: &[u16],
    R: Point<Ed25519>,
) -> Signature {
    let reconstruct_limit = usize::from(vss_sum_local_sigs.parameters.threshold) + 1;
    let gamma_vec: Vec<_> = local_sig_vec[..reconstruct_limit]
        .iter()
        .map(|sig| sig.gamma_i.clone())
        .collect();
    let s = vss_sum_local_sigs.reconstruct(&parties_index_vec[0..reconstruct_limit], &gamma_vec);
    Signature { s, R }
}

mod test;
