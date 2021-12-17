/*
    Multisig ed25519

    Copyright 2018 by Kzen Networks

    This file is part of Multi party eddsa library
    (https://github.com/KZen-networks/multisig-schnorr)

    Multisig Schnorr is free software: you can redistribute
    it and/or modify it under the terms of the GNU General Public
    License as published by the Free Software Foundation, either
    version 3 of the License, or (at your option) any later version.

    @license GPL-3.0+ <https://github.com/KZen-networks/multi-party-ed25519/blob/master/LICENSE>
*/

#[cfg(test)]
mod tests {
    use std::convert::TryInto;

    use curv::cryptographic_primitives::commitments::{
        hash_commitment::HashCommitment, traits::Commitment,
    };
    use curv::elliptic::curves::{Ed25519, Point, Scalar};
    use curv::{arithmetic::Converter, BigInt};
    use hex::decode;
    use itertools::{izip, MultiUnzip};
    use rand::{Rng, RngCore};
    use sha2::Sha512;

    use protocols::tests::deterministic_fast_rand;
    use protocols::{
        aggsig::{self, KeyAgg},
        tests::verify_dalek,
        ExpendedKeyPair, Signature,
    };

    #[test]
    fn test_ed25519_generate_keypair_from_seed() {
        let priv_str = "48ab347b2846f96b7bcd00bf985c52b83b92415c5c914bc1f3b09e186cf2b14f"; // Private Key
        let priv_dec: [u8; 32] = decode(priv_str).unwrap().try_into().unwrap();

        let expected_pubkey_hex =
            "c7d17a93f129527bf7ca413f34a0f23c8462a9c3a3edd4f04550a43cdd60b27a";
        let expected_pubkey = decode(expected_pubkey_hex).unwrap();

        let party1_keys = ExpendedKeyPair::create_from_private_key(priv_dec);
        let mut pubkey = party1_keys.public_key.y_coord().unwrap().to_bytes();
        // Reverse is requried because bigInt returns hex in big endian while pubkeys are usually little endian.
        pubkey.reverse();

        assert_eq!(pubkey, expected_pubkey,);
    }

    #[test]
    fn test_sign_single_verify_dalek() {
        let mut rng = deterministic_fast_rand("test_sign_single_verify_dalek", None);

        let mut msg = [0u8; 64];
        let mut privkey = [0u8; 32];
        for msg_len in 0..msg.len() {
            let msg = &mut msg[..msg_len];
            for _ in 0..20 {
                rng.fill_bytes(&mut privkey);
                rng.fill_bytes(msg);
                let keypair = ExpendedKeyPair::create_from_private_key(privkey);
                let signature = aggsig::sign_single(msg, &keypair);
                assert!(verify_dalek(&keypair.public_key, &signature, msg));
            }
        }
    }

    #[test]
    fn test_sign_aggsig_verify_dalek() {
        let mut rng = deterministic_fast_rand("test_sign_aggsig_verify_dalek", None);

        let mut msg = [0u8; 64];
        const MAX_SIGNERS: usize = 8;
        let mut privkeys = [[0u8; 32]; MAX_SIGNERS];
        for msg_len in 0..msg.len() {
            let msg = &mut msg[..msg_len];
            for signers in 1..MAX_SIGNERS {
                let privkeys = &mut privkeys[..signers];

                privkeys.iter_mut().for_each(|p| rng.fill_bytes(p));
                rng.fill_bytes(msg);
                // Generate keypairs and pubkeys_list from the private keys.
                let keypairs: Vec<_> = privkeys
                    .iter()
                    .copied()
                    .map(ExpendedKeyPair::create_from_private_key)
                    .collect();
                let pubkeys_list: Vec<_> = keypairs.iter().map(|k| k.public_key.clone()).collect();

                // Aggregate the public keys
                let agg_keys: Vec<_> = (0..signers)
                    .map(|i| KeyAgg::key_aggregation_n(&pubkeys_list, i))
                    .collect();

                // Make sure all parties generated the same aggregated public key
                assert!(agg_keys[1..]
                    .iter()
                    .all(|agg_key| agg_key.apk == agg_keys[0].apk));

                // Start signing

                // Generate the first and second messages
                let (Rs, rs, first_msgs, second_msgs): (Vec<_>, Vec<_>, Vec<_>, Vec<_>) = keypairs
                    .iter()
                    .map(|keypair| {
                        let (ephemeral, sign_first, sign_second) =
                            aggsig::create_ephemeral_key_and_commit_rng(keypair, msg, &mut rng);
                        (ephemeral.R, ephemeral.r, sign_first, sign_second)
                    })
                    .multiunzip();
                // Send first first msg, wait to recieve everyone else's and then send second msg.

                // Verify that the second message matches the first message.
                first_msgs
                    .iter()
                    .zip(second_msgs.iter())
                    .for_each(|(first_msg, second_msg)| {
                        assert!(test_com(
                            &second_msg.R,
                            &second_msg.blind_factor,
                            &first_msg.commitment
                        ));
                    });
                // Each party aggregates the Rs to get the aggregate R
                let agg_R = aggsig::get_R_tot(&Rs);

                // keypairs
                let partial_sigs: Vec<_> = izip!(keypairs.iter(), rs.iter(), agg_keys.iter())
                    .map(|(keypair, r, aggkey)| {
                        aggsig::partial_sign(r, keypair, &aggkey.hash, &agg_R, &aggkey.apk, msg)
                    })
                    .collect();

                let signature = aggsig::add_signature_parts(&partial_sigs);
                assert!(verify_dalek(&agg_keys[0].apk, &signature, msg));
            }
        }
    }

    #[test]
    fn test_ed25519_one_party() {
        let message: [u8; 4] = [79, 77, 69, 82];
        let party1_keys = ExpendedKeyPair::create();
        let signature = aggsig::sign_single(&message, &party1_keys);
        assert!(signature.verify(&message, &party1_keys.public_key).is_ok());
    }

    #[test]
    fn test_multiparty_signing_for_two_parties() {
        let mut rng = deterministic_fast_rand("test_multiparty_signing_for_two_parties", None);
        for _i in 0..128 {
            test_multiparty_signing_for_two_parties_internal(&mut rng);
        }
    }

    fn test_multiparty_signing_for_two_parties_internal(rng: &mut impl Rng) {
        let message: [u8; 4] = [79, 77, 69, 82];

        // round 0: generate signing keys
        let party1_key = ExpendedKeyPair::create();
        let party2_key = ExpendedKeyPair::create();

        // round 1: send commitments to ephemeral public keys
        let (party1_ephemeral_key, party1_sign_first_message, party1_sign_second_message) =
            aggsig::create_ephemeral_key_and_commit_rng(&party1_key, &message, rng);
        let (party2_ephemeral_key, party2_sign_first_message, party2_sign_second_message) =
            aggsig::create_ephemeral_key_and_commit_rng(&party2_key, &message, rng);

        let party1_commitment = &party1_sign_first_message.commitment;
        let party2_commitment = &party2_sign_first_message.commitment;

        // round 2: send ephemeral public keys and check commitments
        assert!(test_com(
            &party2_sign_second_message.R,
            &party2_sign_second_message.blind_factor,
            party2_commitment
        ));
        assert!(test_com(
            &party1_sign_second_message.R,
            &party1_sign_second_message.blind_factor,
            party1_commitment
        ));

        // compute apk:
        let pks = [party1_key.public_key.clone(), party2_key.public_key.clone()];
        let party1_key_agg = KeyAgg::key_aggregation_n(&pks, 0);
        let party2_key_agg = KeyAgg::key_aggregation_n(&pks, 1);
        assert_eq!(party1_key_agg.apk, party2_key_agg.apk);
        // compute R' = sum(Ri):
        let Ri = [party1_ephemeral_key.R, party2_ephemeral_key.R];
        // each party i should run this:
        let R_tot = aggsig::get_R_tot(&Ri);
        let s1 = aggsig::partial_sign(
            &party1_ephemeral_key.r,
            &party1_key,
            &party1_key_agg.hash,
            &R_tot,
            &party1_key_agg.apk,
            &message,
        );
        let s2 = aggsig::partial_sign(
            &party2_ephemeral_key.r,
            &party2_key,
            &party2_key_agg.hash,
            &R_tot,
            &party2_key_agg.apk,
            &message,
        );

        let s = [s1, s2];
        let signature = aggsig::add_signature_parts(&s);

        // verify:
        assert!(signature.verify(&message, &party1_key_agg.apk).is_ok())
    }

    #[test]
    fn test_multiparty_signing_for_three_parties() {
        let mut rng = deterministic_fast_rand("test_multiparty_signing_for_three_parties", None);
        for _i in 0..128 {
            test_multiparty_signing_for_three_parties_internal(&mut rng);
        }
    }

    fn test_multiparty_signing_for_three_parties_internal(rng: &mut impl Rng) {
        let message: [u8; 4] = [79, 77, 69, 82];

        // round 0: generate signing keys
        let party1_key = ExpendedKeyPair::create();
        let party2_key = ExpendedKeyPair::create();
        let party3_key = ExpendedKeyPair::create();

        // round 1: send commitments to ephemeral public keys
        let (party1_ephemeral_key, party1_sign_first_message, party1_sign_second_message) =
            aggsig::create_ephemeral_key_and_commit_rng(&party1_key, &message, rng);
        let (party2_ephemeral_key, party2_sign_first_message, party2_sign_second_message) =
            aggsig::create_ephemeral_key_and_commit_rng(&party2_key, &message, rng);
        let (party3_ephemeral_key, party3_sign_first_message, party3_sign_second_message) =
            aggsig::create_ephemeral_key_and_commit_rng(&party3_key, &message, rng);

        let party1_commitment = &party1_sign_first_message.commitment;
        let party2_commitment = &party2_sign_first_message.commitment;
        let party3_commitment = &party3_sign_first_message.commitment;

        // round 2: send ephemeral public keys and check commitments
        assert!(test_com(
            &party2_sign_second_message.R,
            &party2_sign_second_message.blind_factor,
            party2_commitment
        ));
        assert!(test_com(
            &party1_sign_second_message.R,
            &party1_sign_second_message.blind_factor,
            party1_commitment
        ));
        assert!(test_com(
            &party3_sign_second_message.R,
            &party3_sign_second_message.blind_factor,
            party3_commitment
        ));

        // compute apk:
        let pks = [
            party1_key.public_key.clone(),
            party2_key.public_key.clone(),
            party3_key.public_key.clone(),
        ];
        let party1_key_agg = KeyAgg::key_aggregation_n(&pks, 0);
        let party2_key_agg = KeyAgg::key_aggregation_n(&pks, 1);
        let party3_key_agg = KeyAgg::key_aggregation_n(&pks, 2);
        assert_eq!(party1_key_agg.apk, party2_key_agg.apk);
        assert_eq!(party1_key_agg.apk, party3_key_agg.apk);
        // compute R' = sum(Ri):
        let Ri = [
            party1_ephemeral_key.R,
            party2_ephemeral_key.R,
            party3_ephemeral_key.R,
        ];
        // each party i should run this:
        let R_tot = aggsig::get_R_tot(&Ri);
        let s1 = aggsig::partial_sign(
            &party1_ephemeral_key.r,
            &party1_key,
            &party1_key_agg.hash,
            &R_tot,
            &party1_key_agg.apk,
            &message,
        );
        let s2 = aggsig::partial_sign(
            &party2_ephemeral_key.r,
            &party2_key,
            &party2_key_agg.hash,
            &R_tot,
            &party2_key_agg.apk,
            &message,
        );
        let s3 = aggsig::partial_sign(
            &party3_ephemeral_key.r,
            &party3_key,
            &party3_key_agg.hash,
            &R_tot,
            &party3_key_agg.apk,
            &message,
        );

        let s = [s1, s2, s3];
        let signature = aggsig::add_signature_parts(&s);

        // verify:
        assert!(signature.verify(&message, &party1_key_agg.apk).is_ok())
    }

    #[test]
    fn test_verify_standard_sig() {
        // msg hash:05b5d2c43079b8d696ebb21f6e1d1feb7c4aa7c5ba47eea4940f549ebb212e3d
        // sk: ab2add54327c0baa15d21961f820d8fa231de60450dadd7ce2dec12a9934dddc3b97c9279bbb4b501b84d7c3506d5f018a1e1df1d86daab5e97d888af44887eb
        // pk: 3b97c9279bbb4b501b84d7c3506d5f018a1e1df1d86daab5e97d888af44887eb
        // sig: 311b4390d1d92ee3c56d66e22c7cacf13fba86c44b61769b81aa26680af02d1b5a180452743fac943b53728e4cbea288a566ba49f7695808d53b3f9f1cd6ed02
        // R = 311b4390d1d92ee3c56d66e22c7cacf13fba86c44b61769b81aa26680af02d1b
        // s = 5a180452743fac943b53728e4cbea288a566ba49f7695808d53b3f9f1cd6ed02

        let msg_str = "05b5d2c43079b8d696ebb21f6e1d1feb7c4aa7c5ba47eea4940f549ebb212e3d";
        let message = decode(msg_str).unwrap();

        let pk_str = "3b97c9279bbb4b501b84d7c3506d5f018a1e1df1d86daab5e97d888af44887eb";
        let pk_dec = decode(pk_str).unwrap();
        let pk = Point::from_bytes(&pk_dec[..]).unwrap();

        let R_str = "311b4390d1d92ee3c56d66e22c7cacf13fba86c44b61769b81aa26680af02d1b";
        let R_dec = decode(R_str).unwrap();
        let R = Point::from_bytes(&R_dec[..]).unwrap();

        let s_str = "5a180452743fac943b53728e4cbea288a566ba49f7695808d53b3f9f1cd6ed02";
        let mut s_dec = decode(s_str).unwrap();
        s_dec.reverse();
        let s_bn = BigInt::from_bytes(&s_dec[..]);
        let s = Scalar::from(&s_bn);

        let sig = Signature { R, s };
        assert!(sig.verify(&message, &pk).is_ok())
    }

    pub fn test_com(r_to_test: &Point<Ed25519>, blind_factor: &BigInt, comm: &BigInt) -> bool {
        let computed_comm =
            &HashCommitment::<Sha512>::create_commitment_with_user_defined_randomness(
                &r_to_test.y_coord().unwrap(),
                blind_factor,
            );
        computed_comm == comm
    }
}
