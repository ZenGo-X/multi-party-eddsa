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
    use protocols::tests::{deterministic_fast_rand, verify_dalek};
    use protocols::thresholdsig::{
        self, EphemeralKey, EphemeralSharedKeys, Keys, LocalSig, Parameters, SharedKeys,
    };
    use rand::{Rng, RngCore};

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
    // Only run n=6 on release
    #[cfg(not(debug_assertions))]
    fn test_sign_threshold_verify_dalek_n6() {
        test_sign_threshold_verify_dalek_for_all_t(6);
    }

    fn test_sign_threshold_verify_dalek_for_all_t(n: u16) {
        let mut rng = deterministic_fast_rand(
            &format!("test_sign_threshold_verify_dalek_for_all_t_{}", n),
            None,
        );

        // max message size, will try from empty message until full.
        let mut msg = [0u8; 33];

        let indicies: Vec<_> = (1..=n).collect();
        // test all t from 0 to n
        for t in 0..n {
            // KeyGen
            let (keypairs, combined_shares, agg_pubkey, vss_schemes) =
                keygen_t_n_parties(t, n, &indicies, &mut rng);

            // Sign for all possible groups (combinatorially)
            for group in (1u16..=n).combinations(usize::from(t + 1)) {
                let group_indexs: Vec<_> = group.iter().map(|a| a - 1).collect();

                // Try to sign for all possible message lengths from 0 to msg.len()
                for msg_len in 0..msg.len() {
                    let msg = &mut msg[..msg_len];
                    rng.fill_bytes(msg);
                    // Generate Rs
                    let (combined_nonce_shares, agg_nonce, nonce_vss_schemes) =
                        eph_keygen_t_n_parties(t, t + 1, &group, &keypairs, msg, &mut rng);

                    let partial_sigs: Vec<_> = combined_nonce_shares
                        .iter()
                        .zip_eq(group_indexs.iter())
                        .map(|(nonce_share, &index)| {
                            LocalSig::compute(
                                msg,
                                nonce_share,
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
        let mut rng = deterministic_fast_rand("test_t2_n4", None);
        for _i in 0..128 {
            test_t2_n4_internal(&mut rng);
        }
    }

    fn test_t2_n4_internal(rng: &mut impl Rng) {
        // this test assumes that in keygen we have n=4 parties and in signing we have 4 parties as well.
        let t = 2u16;
        let n = 4u16;
        let key_gen_parties_index_vec: [u16; 4] = [0, 1, 2, 3];
        let key_gen_parties_points_vec: Vec<_> =
            key_gen_parties_index_vec.iter().map(|i| i + 1).collect();

        let (priv_keys_vec, priv_shared_keys_vec, Y, key_gen_vss_vec) =
            keygen_t_n_parties(t, n, &key_gen_parties_points_vec, rng);
        let parties_index_vec: [u16; 4] = [0, 1, 2, 3];
        let parties_points_vec: Vec<_> = parties_index_vec.iter().map(|i| i + 1).collect();

        let message: [u8; 4] = [79, 77, 69, 82];
        let (eph_shared_keys_vec, R, eph_vss_vec) =
            eph_keygen_t_n_parties(t, n, &parties_points_vec, &priv_keys_vec, &message, rng);
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
        let mut rng = deterministic_fast_rand("test_t2_n5_sign_with_4", None);
        for _i in 0..128 {
            test_t2_n5_sign_with_4_internal(&mut rng);
        }
    }

    #[allow(unused_doc_comments)]
    fn test_t2_n5_sign_with_4_internal(rng: &mut impl Rng) {
        /// this test assumes that in keygen we have n=4 parties and in signing we have 4 parties, indices 0,1,3,4.
        let t = 2;
        let n = 5;
        /// keygen:
        let key_gen_parties_index_vec: [u16; 5] = [0, 1, 2, 3, 4];
        let key_gen_parties_points_vec: Vec<_> =
            key_gen_parties_index_vec.iter().map(|i| i + 1).collect();
        let (priv_keys_vec, priv_shared_keys_vec, Y, key_gen_vss_vec) =
            keygen_t_n_parties(t, n, &key_gen_parties_points_vec, rng);
        /// signing:
        let parties_index_vec: [u16; 4] = [0, 1, 3, 4];
        let parties_points_vec: Vec<_> = parties_index_vec.iter().map(|i| i + 1).collect();
        let num_parties = parties_index_vec.len() as u16;
        let message: [u8; 4] = [79, 77, 69, 82];

        let (eph_shared_keys_vec, R, eph_vss_vec) = eph_keygen_t_n_parties(
            t,
            num_parties,
            &parties_points_vec,
            &priv_keys_vec,
            &message,
            rng,
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
        rng: &mut impl Rng,
    ) -> (
        Vec<Keys>,
        Vec<SharedKeys>,
        Point<Ed25519>,
        Vec<VerifiableSS<Ed25519>>,
    ) {
        let params = Parameters {
            threshold: t,
            share_count: n,
        };
        assert_eq!(parties.len(), usize::from(n));
        let keypairs: Vec<_> = parties.iter().copied().map(Keys::phase1_create).collect();

        let (first_msgs, first_msg_blinds): (Vec<_>, Vec<_>) = keypairs
            .iter()
            .map(|keypair| Keys::phase1_broadcast_rng(keypair, rng))
            .unzip();

        let pubkeys_list: Vec<_> = keypairs
            .iter()
            .map(|k| k.keypair.public_key.clone())
            .collect();

        // Generate the aggregate key
        let agg_pubkey = {
            let first_key = pubkeys_list[0].clone();
            pubkeys_list[1..].iter().fold(first_key, |acc, p| acc + p)
        };
        let (vss_schemes, secret_shares): (Vec<_>, Vec<_>) = keypairs
            .iter()
            .map(|keypair| {
                keypair
                    .phase1_verify_com_phase2_distribute(
                        &params,
                        &first_msg_blinds,
                        &pubkeys_list,
                        &first_msgs,
                        parties,
                    )
                    .unwrap()
            })
            .unzip();

        let parties_shares: Vec<Vec<_>> = (0..usize::from(n))
            .map(|i| {
                (0..usize::from(n))
                    .map(|j| secret_shares[j][i].clone())
                    .collect()
            })
            .collect();

        let combined_shares: Vec<_> = izip!(keypairs.iter(), parties_shares.iter(), parties.iter())
            .map(|(keypair, secret_shares, &index)| {
                keypair
                    .phase2_verify_vss_construct_keypair(
                        &params,
                        &pubkeys_list,
                        secret_shares,
                        &vss_schemes,
                        index,
                    )
                    .unwrap()
            })
            .collect();

        (keypairs, combined_shares, agg_pubkey, vss_schemes)
    }

    pub fn eph_keygen_t_n_parties(
        t: u16, // system threshold
        n: u16, // number of signers
        parties: &[u16],
        keypairs: &[Keys],
        message: &[u8],
        rng: &mut impl Rng,
    ) -> (
        Vec<EphemeralSharedKeys>,
        Point<Ed25519>,
        Vec<VerifiableSS<Ed25519>>,
    ) {
        assert!(parties.len() > usize::from(t) && parties.len() <= usize::from(n));
        let params = Parameters {
            threshold: t,
            share_count: n,
        };
        // Generate Rs
        let (Rs, nonce_keys): (Vec<_>, Vec<_>) = parties
            .iter()
            .map(|&index| {
                let ephemeral_key =
                    EphemeralKey::ephermeral_key_create_from_deterministic_secret_rng(
                        &keypairs[usize::from(index - 1)],
                        message,
                        index,
                        rng,
                    );
                (ephemeral_key.R_i.clone(), ephemeral_key)
            })
            .unzip();

        // Generate first messages
        let (first_msgs, first_msg_blinds): (Vec<_>, Vec<_>) = nonce_keys
            .iter()
            .map(|nonce| EphemeralKey::phase1_broadcast_rng(nonce, rng))
            .unzip();

        // Generate the aggregate nonce point
        let agg_nonce = {
            let first_key = Rs[0].clone();
            Rs[1..].iter().fold(first_key, |acc, p| acc + p)
        };
        // Verify the first messages and generate the vss and secret shares
        let (nonce_vss_schemes, nonce_secret_shares): (Vec<_>, Vec<_>) = nonce_keys
            .iter()
            .map(|nonce| {
                nonce
                    .phase1_verify_com_phase2_distribute(
                        &params,
                        &first_msg_blinds,
                        &Rs,
                        &first_msgs,
                        parties,
                    )
                    .unwrap()
            })
            .unzip();

        let nonce_parties_shares: Vec<Vec<_>> = (0..usize::from(n))
            .map(|i| {
                (0..usize::from(n))
                    .map(|j| nonce_secret_shares[j][i].clone())
                    .collect()
            })
            .collect();

        let combined_nonce_shares: Vec<_> = izip!(
            nonce_keys.iter(),
            nonce_parties_shares.iter(),
            parties.iter()
        )
        .map(|(nonce, nonce_secret_share, &index)| {
            nonce
                .phase2_verify_vss_construct_keypair(
                    &params,
                    &Rs,
                    nonce_secret_share,
                    &nonce_vss_schemes,
                    index,
                )
                .unwrap()
        })
        .collect();

        (combined_nonce_shares, agg_nonce, nonce_vss_schemes)
    }
}
