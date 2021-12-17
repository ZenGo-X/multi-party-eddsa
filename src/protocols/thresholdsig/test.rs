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
#[cfg(test)]
mod tests {
    use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
    use curv::elliptic::curves::{Ed25519, Point};
    use itertools::{izip, Itertools};
    use protocols::tests::verify_dalek;
    use protocols::thresholdsig::{
        self, EphemeralKey, EphemeralSharedKeys, Keys, LocalSig, Parameters, SharedKeys,
    };
    use rand::{thread_rng, RngCore};

    #[test]
    fn test_sign_threshold_verify_dalek_n1() {
        test_sign_threshold_verify_dalek_for_all_t(1);
    }
    #[test]
    fn test_sign_threshold_verify_dalek_n2() {
        test_sign_threshold_verify_dalek_for_all_t(2);
    }
    #[test]
    fn test_sign_threshold_verify_dalek_n3() {
        test_sign_threshold_verify_dalek_for_all_t(3);
    }
    #[test]
    fn test_sign_threshold_verify_dalek_n4() {
        test_sign_threshold_verify_dalek_for_all_t(4);
    }
    #[test]
    fn test_sign_threshold_verify_dalek_n5() {
        test_sign_threshold_verify_dalek_for_all_t(5);
    }

    #[test]
    fn test_sign_threshold_verify_dalek_n6() {
        test_sign_threshold_verify_dalek_for_all_t(6);
    }

    fn test_sign_threshold_verify_dalek_for_all_t(n: u16) {
        // max message size, will try from empty message until full.
        let mut msg = [0u8; 33];

        let mut rng = thread_rng();
        let indicies: Vec<_> = (1..=n).collect();
        // test all t from 0 to n
        for t in 0..n {
            // KeyGen
            let (keypairs, combined_shares, agg_pubkey, vss_schemes) =
                keygen_t_n_parties(t, n, &indicies);

            // Sign for all possible groups (combinatorially)
            for group in (1u16..=n).combinations(usize::from(t + 1)) {
                let group_indexs: Vec<_> = group.iter().map(|a| a - 1).collect();

                // Try to sign for all possible message lengths from 0 to msg.len()
                for msg_len in 0..msg.len() {
                    let msg = &mut msg[..msg_len];
                    rng.fill_bytes(msg);
                    // Generate Rs
                    let (combined_nonce_shares, agg_nonce, nonce_vss_schemes) =
                        eph_keygen_t_n_parties(t, t + 1, &group, &keypairs, msg);

                    let partial_sigs: Vec<_> = combined_nonce_shares
                        .iter()
                        .zip_eq(group_indexs.iter())
                        .map(|(nonce_share, &index)| {
                            LocalSig::compute(
                                msg,
                                &nonce_share,
                                &combined_shares[usize::from(index)],
                            )
                        })
                        .collect();

                    // Verify all partial signatures
                    let vss_sum_sigs = LocalSig::verify_local_sigs(
                        &partial_sigs,
                        &group_indexs,
                        &vss_schemes,
                        &nonce_vss_schemes,
                    )
                    .unwrap();
                    let sig = thresholdsig::generate(
                        &vss_sum_sigs,
                        &partial_sigs,
                        &group_indexs,
                        agg_nonce,
                    );
                    assert!(verify_dalek(&agg_pubkey, &sig, msg));
                }
            }
        }
    }

    #[test]
    fn test_t2_n4() {
        for _i in 0..256 {
            test_t2_n4_internal();
        }
    }

    fn test_t2_n4_internal() {
        // this test assumes that in keygen we have n=4 parties and in signing we have 4 parties as well.
        let t = 2u16;
        let n = 4u16;
        let key_gen_parties_index_vec: [u16; 4] = [0, 1, 2, 3];
        let key_gen_parties_points_vec = (0..key_gen_parties_index_vec.len())
            .map(|i| key_gen_parties_index_vec[i].clone() + 1)
            .collect::<Vec<_>>();

        let (priv_keys_vec, priv_shared_keys_vec, Y, key_gen_vss_vec) =
            keygen_t_n_parties(t.clone(), n.clone(), &key_gen_parties_points_vec);
        let parties_index_vec: [u16; 4] = [0, 1, 2, 3];
        let parties_points_vec = (0..parties_index_vec.len())
            .map(|i| parties_index_vec[i].clone() + 1)
            .collect::<Vec<u16>>();

        let message: [u8; 4] = [79, 77, 69, 82];
        let (_eph_keys_vec, eph_shared_keys_vec, R, eph_vss_vec) = eph_keygen_t_n_parties(
            t.clone(),
            n.clone(),
            &parties_points_vec,
            &priv_keys_vec,
            &message,
        );
        let local_sig_vec = (0..usize::from(n))
            .map(|i| LocalSig::compute(&message, &eph_shared_keys_vec[i], &priv_shared_keys_vec[i]))
            .collect::<Vec<LocalSig>>();
        let verify_local_sig = LocalSig::verify_local_sigs(
            &local_sig_vec,
            &parties_index_vec,
            &key_gen_vss_vec,
            &eph_vss_vec,
        );

        assert!(verify_local_sig.is_ok());
        let vss_sum_local_sigs = verify_local_sig.unwrap();
        let signature =
            thresholdsig::generate(&vss_sum_local_sigs, &local_sig_vec, &parties_index_vec, R);
        let verify_sig = signature.verify(&message, &Y);
        assert!(verify_sig.is_ok());
    }

    #[test]
    fn test_t2_n5_sign_with_4() {
        for _i in 0..256 {
            test_t2_n5_sign_with_4_internal();
        }
    }

    #[allow(unused_doc_comments)]
    fn test_t2_n5_sign_with_4_internal() {
        /// this test assumes that in keygen we have n=4 parties and in signing we have 4 parties, indices 0,1,3,4.
        let t = 2;
        let n = 5;
        /// keygen:
        let key_gen_parties_index_vec: [u16; 5] = [0, 1, 2, 3, 4];
        let key_gen_parties_points_vec = (0..key_gen_parties_index_vec.len())
            .map(|i| key_gen_parties_index_vec[i].clone() + 1)
            .collect::<Vec<_>>();
        let (priv_keys_vec, priv_shared_keys_vec, Y, key_gen_vss_vec) =
            keygen_t_n_parties(t.clone(), n.clone(), &key_gen_parties_points_vec);
        /// signing:
        let parties_index_vec: [u16; 4] = [0, 1, 3, 4];
        let parties_points_vec = (0..parties_index_vec.len())
            .map(|i| parties_index_vec[i].clone() + 1)
            .collect::<Vec<_>>();
        let num_parties = parties_index_vec.len() as u16;
        let message: [u8; 4] = [79, 77, 69, 82];

        let (_eph_keys_vec, eph_shared_keys_vec, R, eph_vss_vec) = eph_keygen_t_n_parties(
            t.clone(),
            num_parties.clone(),
            &parties_points_vec,
            &priv_keys_vec,
            &message,
        );

        // each party computes and share a local sig, we collected them here to a vector as each party should do AFTER receiving all local sigs
        let local_sig_vec = (0..usize::from(num_parties))
            .map(|i| {
                LocalSig::compute(
                    &message,
                    &eph_shared_keys_vec[i],
                    &priv_shared_keys_vec[usize::from(parties_index_vec[i])],
                )
            })
            .collect::<Vec<LocalSig>>();

        let verify_local_sig = LocalSig::verify_local_sigs(
            &local_sig_vec,
            &parties_index_vec,
            &key_gen_vss_vec,
            &eph_vss_vec,
        );

        assert!(verify_local_sig.is_ok());
        let vss_sum_local_sigs = verify_local_sig.unwrap();

        /// each party / dealer can generate the signature
        let signature =
            thresholdsig::generate(&vss_sum_local_sigs, &local_sig_vec, &parties_index_vec, R);
        let verify_sig = signature.verify(&message, &Y);
        assert!(verify_sig.is_ok());
    }

    pub fn keygen_t_n_parties(
        t: u16,
        n: u16,
        parties: &[u16],
    ) -> (
        Vec<Keys>,
        Vec<SharedKeys>,
        Point<Ed25519>,
        Vec<VerifiableSS<Ed25519>>,
    ) {
        let parames = Parameters {
            threshold: t,
            share_count: n.clone(),
        };
        assert_eq!(parties.len(), usize::from(n));
        let party_keys_vec = (0..usize::from(n))
            .map(|i| Keys::phase1_create(parties[i]))
            .collect::<Vec<Keys>>();

        let mut bc1_vec = Vec::new();
        let mut blind_vec = Vec::new();
        for i in 0..usize::from(n) {
            let (bc1, blind) = party_keys_vec[i].phase1_broadcast();
            bc1_vec.push(bc1);
            blind_vec.push(blind);
        }

        let y_vec = (0..usize::from(n))
            .map(|i| party_keys_vec[i].keypair.public_key.clone())
            .collect::<Vec<_>>();
        let mut y_vec_iter = y_vec.iter();
        let head = y_vec_iter.next().unwrap();
        let tail = y_vec_iter;
        let y_sum = tail.fold(head.clone(), |acc, x| acc + x);
        let mut vss_scheme_vec = Vec::new();
        let mut secret_shares_vec = Vec::new();
        let mut index_vec = Vec::new();
        for i in 0..usize::from(n) {
            let (vss_scheme, secret_shares, index) = party_keys_vec[i]
                .phase1_verify_com_phase2_distribute(
                    &parames, &blind_vec, &y_vec, &bc1_vec, parties,
                )
                .expect("invalid key");
            vss_scheme_vec.push(vss_scheme);
            secret_shares_vec.push(secret_shares);
            index_vec.push(index);
        }

        let party_shares = (0..usize::from(n))
            .map(|i| {
                (0..usize::from(n))
                    .map(|j| {
                        let vec_j = &secret_shares_vec[j];
                        vec_j[i].clone()
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<Vec<_>>>();

        let mut shared_keys_vec = Vec::new();
        for i in 0..usize::from(n) {
            let shared_keys = party_keys_vec[i]
                .phase2_verify_vss_construct_keypair(
                    &parames,
                    &y_vec,
                    &party_shares[i],
                    &vss_scheme_vec,
                    &index_vec[i],
                )
                .expect("invalid vss");
            shared_keys_vec.push(shared_keys);
        }

        (party_keys_vec, shared_keys_vec, y_sum, vss_scheme_vec)
    }

    pub fn eph_keygen_t_n_parties(
        t: u16, // system threshold
        n: u16, // number of signers
        parties: &[u16],
        keys_vec: &Vec<Keys>,
        message: &[u8],
    ) -> (
        Vec<EphemeralKey>,
        Vec<EphemeralSharedKeys>,
        Point<Ed25519>,
        Vec<VerifiableSS<Ed25519>>,
    ) {
        let parames = Parameters {
            threshold: t,
            share_count: n.clone(),
        };
        assert!(parties.len() > usize::from(t) && parties.len() <= usize::from(n));
        let eph_party_keys_vec = (0..usize::from(n))
            .map(|i| {
                EphemeralKey::ephermeral_key_create_from_deterministic_secret(
                    &keys_vec[i],
                    message,
                    parties[i],
                )
            })
            .collect::<Vec<EphemeralKey>>();

        let mut bc1_vec = Vec::new();
        let mut blind_vec = Vec::new();
        for i in 0..usize::from(n) {
            let (bc1, blind) = eph_party_keys_vec[i].phase1_broadcast();
            bc1_vec.push(bc1);
            blind_vec.push(blind);
        }

        let R_vec = (0..usize::from(n))
            .map(|i| eph_party_keys_vec[i].R_i.clone())
            .collect::<Vec<_>>();
        let mut R_vec_iter = R_vec.iter();
        let head = R_vec_iter.next().unwrap();
        let tail = R_vec_iter;
        let R_sum = tail.fold(head.clone(), |acc, x| acc + x);
        let mut vss_scheme_vec = Vec::new();
        let mut secret_shares_vec = Vec::new();
        let mut index_vec = Vec::new();
        for i in 0..usize::from(n) {
            let (vss_scheme, secret_shares, index) = eph_party_keys_vec[i]
                .phase1_verify_com_phase2_distribute(
                    &parames, &blind_vec, &R_vec, &bc1_vec, parties,
                )
                .expect("invalid key");
            vss_scheme_vec.push(vss_scheme);
            secret_shares_vec.push(secret_shares);
            index_vec.push(index);
        }

        let party_shares = (0..usize::from(n))
            .map(|i| {
                (0..usize::from(n))
                    .map(|j| {
                        let vec_j = &secret_shares_vec[j];
                        vec_j[i].clone()
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<Vec<_>>>();

        let mut shared_keys_vec = Vec::new();
        for i in 0..usize::from(n) {
            let shared_keys = eph_party_keys_vec[i]
                .phase2_verify_vss_construct_keypair(
                    &parames,
                    &R_vec,
                    &party_shares[i],
                    &vss_scheme_vec,
                    &index_vec[i],
                )
                .expect("invalid vss");
            shared_keys_vec.push(shared_keys);
        }

        (eph_party_keys_vec, shared_keys_vec, R_sum, vss_scheme_vec)
    }
}
