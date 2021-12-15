#![allow(non_snake_case)]
#[allow(unused_doc_comments)]
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
use Error::{self, InvalidKey, InvalidSS, InvalidSig};

use curv::arithmetic::traits::*;
use curv::cryptographic_primitives::commitments::hash_commitment::HashCommitment;
use curv::cryptographic_primitives::commitments::traits::Commitment;
use curv::cryptographic_primitives::hashing::DigestExt;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::{SecretShares, VerifiableSS};
use curv::elliptic::curves::{Ed25519, Point, Scalar};
use curv::BigInt;
use sha2::{digest::Digest, Sha512};

const SECURITY: usize = 256;

// u_i is private key and {u__i, prefix} are extended private key.
pub struct Keys {
    pub u_i: Scalar<Ed25519>,
    pub y_i: Point<Ed25519>,
    pub prefix: Scalar<Ed25519>,
    pub party_index: u16,
}

pub struct KeyGenBroadcastMessage1 {
    com: BigInt,
}

#[derive(Debug)]
pub struct Parameters {
    pub threshold: u16,   //t
    pub share_count: u16, //n
}
#[derive(Clone, Serialize, Deserialize)]
pub struct SharedKeys {
    pub y: Point<Ed25519>,
    pub x_i: Scalar<Ed25519>,
    prefix: Scalar<Ed25519>,
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

pub struct LocalSig {
    gamma_i: Scalar<Ed25519>,
    k: Scalar<Ed25519>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Signature {
    pub sigma: Scalar<Ed25519>,
    pub R: Point<Ed25519>,
}

impl Keys {
    pub fn phase1_create(index: u16) -> Keys {
        let sk: Scalar<Ed25519> = Scalar::random();
        Self::phase1_create_from_private_key_internal(index, &sk)
    }

    pub fn phase1_create_from_private_key(index: u16, secret: &BigInt) -> Keys {
        let sk: Scalar<Ed25519> = Scalar::from(secret);
        Self::phase1_create_from_private_key_internal(index, &sk)
    }

    fn phase1_create_from_private_key_internal(index: u16, sk: &Scalar<Ed25519>) -> Keys {
        let ec_point = Point::generator();
        let h = Sha512::new().chain_scalar(sk).result_bigint();
        let h_vec = BigInt::to_bytes(&h);
        let mut h_vec_padded = vec![0; 64 - h_vec.len()]; // ensure hash result is padded to 64 bytes
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
        let private_key: Scalar<Ed25519> = Scalar::from(&BigInt::from_bytes(private_key));
        let prefix: Scalar<Ed25519> = Scalar::from(&BigInt::from_bytes(prefix));
        let public_key = ec_point * &private_key;

        Keys {
            u_i: private_key,
            y_i: public_key,
            prefix,
            party_index: index.clone(),
        }
    }

    pub fn phase1_broadcast(&self) -> (KeyGenBroadcastMessage1, BigInt) {
        let blind_factor = BigInt::sample(SECURITY);
        let com = HashCommitment::<Sha512>::create_commitment_with_user_defined_randomness(
            &self.y_i.y_coord().unwrap(),
            &blind_factor,
        );
        let bcm1 = KeyGenBroadcastMessage1 { com };
        (bcm1, blind_factor)
    }

    pub fn phase1_verify_com_phase2_distribute(
        &self,
        params: &Parameters,
        blind_vec: &Vec<BigInt>,
        y_vec: &Vec<Point<Ed25519>>,
        bc1_vec: &Vec<KeyGenBroadcastMessage1>,
        parties: &[u16],
    ) -> Result<(VerifiableSS<Ed25519>, SecretShares<Ed25519>, u16), Error> {
        // test length:
        assert_eq!(blind_vec.len(), usize::from(params.share_count));
        assert_eq!(bc1_vec.len(), usize::from(params.share_count));
        assert_eq!(y_vec.len(), usize::from(params.share_count));
        // test decommitments
        let correct_key_correct_decom_all = (0..bc1_vec.len())
            .map(|i| {
                HashCommitment::<Sha512>::create_commitment_with_user_defined_randomness(
                    &y_vec[i].y_coord().unwrap(),
                    &blind_vec[i],
                ) == bc1_vec[i].com
            })
            .all(|x| x == true);

        let (vss_scheme, secret_shares) = VerifiableSS::share_at_indices(
            params.threshold,
            params.share_count,
            &self.u_i,
            &parties,
        );

        match correct_key_correct_decom_all {
            true => Ok((vss_scheme, secret_shares, self.party_index.clone())),
            false => Err(InvalidKey),
        }
    }

    pub fn phase2_verify_vss_construct_keypair(
        &self,
        params: &Parameters,
        y_vec: &Vec<Point<Ed25519>>,
        secret_shares_vec: &Vec<Scalar<Ed25519>>,
        vss_scheme_vec: &Vec<VerifiableSS<Ed25519>>,
        index: &u16,
    ) -> Result<SharedKeys, Error> {
        assert_eq!(y_vec.len(), usize::from(params.share_count));
        assert_eq!(secret_shares_vec.len(), usize::from(params.share_count));
        assert_eq!(vss_scheme_vec.len(), usize::from(params.share_count));

        let correct_ss_verify = (0..y_vec.len())
            .map(|i| {
                vss_scheme_vec[i]
                    .validate_share(&secret_shares_vec[i], *index)
                    .is_ok()
                    && vss_scheme_vec[i].commitments[0] == y_vec[i]
            })
            .all(|x| x == true);

        match correct_ss_verify {
            true => {
                let mut y_vec_iter = y_vec.iter();
                let y0 = y_vec_iter.next().unwrap();
                let y = y_vec_iter.fold(y0.clone(), |acc, x| acc + x);
                let x_i = secret_shares_vec
                    .iter()
                    .fold(Scalar::zero(), |acc, x| acc + x);
                Ok(SharedKeys {
                    y,
                    x_i,
                    prefix: self.prefix.clone(),
                })
            }
            false => Err(InvalidSS),
        }
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
        // here we deviate from the spec, by introducing  non-deterministic element (random number)
        // to the nonce
        let r_local = Sha512::new()
            .chain_scalar(&keys.prefix)
            .chain(message)
            .chain_scalar(&Scalar::<Ed25519>::random())
            .result_bigint();
        let r_i = Scalar::from_bigint(&r_local);
        let R_i = Point::generator() * &r_i;

        EphemeralKey {
            r_i,
            R_i,
            party_index: index,
        }
    }

    pub fn phase1_broadcast(&self) -> (KeyGenBroadcastMessage1, BigInt) {
        let blind_factor = BigInt::sample(SECURITY);
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
        blind_vec: &Vec<BigInt>,
        R_vec: &Vec<Point<Ed25519>>,
        bc1_vec: &Vec<KeyGenBroadcastMessage1>,
        parties: &[u16],
    ) -> Result<(VerifiableSS<Ed25519>, SecretShares<Ed25519>, u16), Error> {
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
        let correct_key_correct_decom_all = (0..bc1_vec.len())
            .map(|i| {
                HashCommitment::<Sha512>::create_commitment_with_user_defined_randomness(
                    &R_vec[i].y_coord().unwrap(),
                    &blind_vec[i],
                ) == bc1_vec[i].com
            })
            .all(|x| x == true);

        let (vss_scheme, secret_shares) = VerifiableSS::share_at_indices(
            params.threshold,
            params.share_count,
            &self.r_i,
            &parties,
        );

        match correct_key_correct_decom_all {
            true => Ok((vss_scheme, secret_shares, self.party_index.clone())),
            false => Err(InvalidKey),
        }
    }

    pub fn phase2_verify_vss_construct_keypair(
        &self,
        params: &Parameters,
        R_vec: &Vec<Point<Ed25519>>,
        secret_shares_vec: &Vec<Scalar<Ed25519>>,
        vss_scheme_vec: &Vec<VerifiableSS<Ed25519>>,
        index: &u16,
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

        let correct_ss_verify = (0..R_vec.len())
            .map(|i| {
                vss_scheme_vec[i]
                    .validate_share(&secret_shares_vec[i], *index)
                    .is_ok()
                    && vss_scheme_vec[i].commitments[0] == R_vec[i]
            })
            .all(|x| x == true);

        match correct_ss_verify {
            true => {
                let mut R_vec_iter = R_vec.iter();
                let R0 = R_vec_iter.next().unwrap();
                let R = R_vec_iter.fold(R0.clone(), |acc, x| acc + x);
                let r_i = secret_shares_vec
                    .iter()
                    .fold(Scalar::zero(), |acc, x| acc + x);
                Ok(EphemeralSharedKeys { R, r_i })
            }
            false => Err(InvalidSS),
        }
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

        let e_bn = Sha512::new()
            .chain_point(&local_ephemaral_key.R)
            .chain_point(&local_private_key.y)
            .chain(message)
            .result_bigint();
        let k = Scalar::from_bigint(&e_bn);
        let gamma_i = r_i + &k * s_i;

        LocalSig { gamma_i, k }
    }

    // section 4.2 step 3
    #[allow(unused_doc_comments)]
    pub fn verify_local_sigs(
        gamma_vec: &Vec<LocalSig>,
        parties_index_vec: &[u16],
        vss_private_keys: &Vec<VerifiableSS<Ed25519>>,
        vss_ephemeral_keys: &Vec<VerifiableSS<Ed25519>>,
    ) -> Result<VerifiableSS<Ed25519>, Error> {
        //parties_index_vec is a vector with indices of the parties that are participating and provided gamma_i for this step
        // test that enough parties are in this round
        assert!(parties_index_vec.len() > usize::from(vss_private_keys[0].parameters.threshold));

        // Vec of joint commitments:
        // n' = num of signers, n - num of parties in keygen
        // [com0_eph_0,... ,com0_eph_n', e*com0_kg_0, ..., e*com0_kg_n ;
        // ...  ;
        // comt_eph_0,... ,comt_eph_n', e*comt_kg_0, ..., e*comt_kg_n ]
        let comm_vec = (0..usize::from(vss_private_keys[0].parameters.threshold) + 1)
            .map(|i| {
                let mut key_gen_comm_i_vec = (0..vss_private_keys.len())
                    .map(|j| vss_private_keys[j].commitments[i].clone() * &gamma_vec[i].k)
                    .collect::<Vec<Point<Ed25519>>>();
                let mut eph_comm_i_vec = (0..vss_ephemeral_keys.len())
                    .map(|j| vss_ephemeral_keys[j].commitments[i].clone())
                    .collect::<Vec<Point<Ed25519>>>();
                key_gen_comm_i_vec.append(&mut eph_comm_i_vec);
                let mut comm_i_vec_iter = key_gen_comm_i_vec.iter();
                let comm_i_0 = comm_i_vec_iter.next().unwrap();
                comm_i_vec_iter.fold(comm_i_0.clone(), |acc, x| acc + x)
            })
            .collect::<Vec<Point<Ed25519>>>();

        let vss_sum = VerifiableSS {
            parameters: vss_ephemeral_keys[0].parameters.clone(),
            commitments: comm_vec,
        };

        let g = Point::<Ed25519>::generator();
        let correct_ss_verify = (0..parties_index_vec.len())
            .map(|i| {
                let gamma_i_g = &gamma_vec[i].gamma_i * g;
                vss_sum
                    .validate_share_public(&gamma_i_g, parties_index_vec[i] + 1)
                    .is_ok()
            })
            .collect::<Vec<bool>>();

        match correct_ss_verify.iter().all(|x| x.clone() == true) {
            true => Ok(vss_sum),
            false => Err(InvalidSS),
        }
    }
}

impl Signature {
    pub fn generate(
        vss_sum_local_sigs: &VerifiableSS<Ed25519>,
        local_sig_vec: &Vec<LocalSig>,
        parties_index_vec: &[u16],
        R: Point<Ed25519>,
    ) -> Signature {
        let gamma_vec = (0..parties_index_vec.len())
            .map(|i| local_sig_vec[i].gamma_i.clone())
            .collect::<Vec<Scalar<Ed25519>>>();
        let reconstruct_limit = usize::from(vss_sum_local_sigs.parameters.threshold) + 1;
        let sigma = vss_sum_local_sigs.reconstruct(
            &parties_index_vec[0..reconstruct_limit],
            &gamma_vec[0..reconstruct_limit],
        );
        Signature { sigma, R }
    }

    pub fn verify(&self, message: &[u8], pubkey_y: &Point<Ed25519>) -> Result<(), Error> {
        let e_bn = Sha512::new()
            .chain_point(&self.R)
            .chain_point(pubkey_y)
            .chain(message)
            .result_bigint();

        let e: Scalar<Ed25519> = Scalar::from(&e_bn);

        let g = Point::generator();
        let sigma_g = g * &self.sigma;
        let e_y = pubkey_y * &e;
        let e_y_plus_v = e_y + &self.R;

        if e_y_plus_v == sigma_g {
            Ok(())
        } else {
            Err(InvalidSig)
        }
    }
}

mod test;
