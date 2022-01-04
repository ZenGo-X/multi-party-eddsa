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
    use curv::elliptic::curves::{Ed25519, Point, Scalar};
    use curv::{arithmetic::Converter, BigInt};
    use hex::decode;
    use itertools::{izip, MultiUnzip};
    use rand::{Rng, RngCore};
    use sha2::Sha512;
    use std::convert::TryInto;

    use protocols::tests::deterministic_fast_rand;
    use protocols::{
        musig2::{self, PartialNonces, PublicKeyAgg},
        tests::verify_dalek,
        ExpandedKeyPair, Signature,
    };

    #[test]
    fn test_ed25519_generate_keypair_from_seed() {
        let priv_str = "48ab347b2846f96b7bcd00bf985c52b83b92415c5c914bc1f3b09e186cf2b14f"; // Private Key
        let priv_dec: [u8; 32] = decode(priv_str).unwrap().try_into().unwrap();

        let expected_pubkey_hex =
            "c7d17a93f129527bf7ca413f34a0f23c8462a9c3a3edd4f04550a43cdd60b27a";
        let expected_pubkey = decode(expected_pubkey_hex).unwrap();

        let party1_keys = ExpandedKeyPair::create_from_private_key(priv_dec);
        let mut pubkey = party1_keys.public_key.y_coord().unwrap().to_bytes();
        // Reverse is requried because bigInt returns hex in big endian while pubkeys are usually little endian.
        pubkey.reverse();

        assert_eq!(pubkey, expected_pubkey,);
    }

    #[test]
    fn test_sign_musig2_verify_dalek() {
        let mut rng = deterministic_fast_rand("test_sign_musig2_verify_dalek", None);

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
                    .map(ExpandedKeyPair::create_from_private_key)
                    .collect();
                let pubkeys_list: Vec<_> = keypairs.iter().map(|k| k.public_key.clone()).collect();

                // Aggregate the public keys
                let agg_pub_keys: Vec<_> = (0..signers)
                    .map(|i| PublicKeyAgg::key_aggregation_n(pubkeys_list.clone(), i))
                    .collect();

                // Make sure all parties generated the same aggregated public key
                assert!(agg_pub_keys[1..]
                    .iter()
                    .all(|agg_key| agg_key.agg_public_key == agg_pub_keys[0].agg_public_key));

                // Generate the first messages - (partial nonces)
                let partial_nonces: Vec<_> = keypairs
                    .iter()
                    .map(|keypair| {
                        musig2::generate_partial_nonces(keypair, Option::Some(msg), &mut rng)
                    })
                    .collect();
                // Send partial nonces to everyone and wait to receive everyone else's

                // Compute partial signatures
                let partial_sigs: Vec<_> = keypairs
                    .iter()
                    .enumerate()
                    .map(|(index, keypair)| {
                        let mut partial_nonces_without_signer = partial_nonces.clone();
                        let my_partial_nonces = partial_nonces_without_signer.remove(index);
                        let partial_nonce_slice = partial_nonces_without_signer
                            .iter()
                            .map(|partial_nonce| partial_nonce.R.clone())
                            .collect::<Vec<_>>();

                        musig2::partial_sign(
                            partial_nonce_slice.as_slice(),
                            my_partial_nonces,
                            &agg_pub_keys[0],
                            keypair,
                            msg,
                        )
                    })
                    .collect();
                
                // Compute signature
                let signatures: Vec<_> = (0..signers)
                    .into_iter()
                    .map(|index| {
                        let mut partial_sigs_without_signer = partial_sigs.clone();
                        let my_partial_sig = partial_sigs_without_signer.remove(index);
                        let partial_sig_slice = partial_sigs_without_signer
                            .iter()
                            .map(|partial_sig_other| partial_sig_other.my_partial_s.clone())
                            .collect::<Vec<_>>();

                        musig2::aggregate_partial_signatures(
                            &my_partial_sig,
                            partial_sig_slice.as_slice(),
                        )
                    })
                    .collect();

                // Make sure all parties generated the same signature
                assert!(signatures[1..].iter().all(|sig| sig == &signatures[0]));
                
                // Verify signature
                assert!(signatures[0].verify(msg, &agg_pub_keys[0].agg_public_key).is_ok(), "Signature verification failed!");

                // Verify result against dalek
                assert!(verify_dalek(
                    &agg_pub_keys[0].agg_public_key,
                    &signatures[0],
                    msg
                ), "Dalek signature verification failed!");
            }
        }
    }

    #[test]
    fn test_multiparty_signing_for_two_parties() {
        let mut rng = deterministic_fast_rand("test_multiparty_signing_for_two_parties", None);
        for _i in 0..1 {
            test_multiparty_signing_for_two_parties_internal(&mut rng);
        }
    }

    fn test_multiparty_signing_for_two_parties_internal(rng: &mut impl Rng) {
        let message: [u8; 12] = [79, 77, 69, 82, 60, 61, 100, 156, 109, 125, 3, 19];

        // round 0: generate signing keys generate nonces
        let party0_key = ExpandedKeyPair::create();
        let party1_key = ExpandedKeyPair::create();

        let p0_partial_nonces = musig2::generate_partial_nonces(&party0_key, Option::Some(&message), rng);
        let p1_partial_nonces = musig2::generate_partial_nonces(&party1_key, Option::Some(&message), rng);

        // compute aggregated public key:
        let pks = vec![party0_key.public_key.clone(), party1_key.public_key.clone()];
        let party0_key_agg = PublicKeyAgg::key_aggregation_n(pks.clone(), 0);
        let party1_key_agg = PublicKeyAgg::key_aggregation_n(pks, 1);
        assert_eq!(party0_key_agg.agg_public_key, party1_key_agg.agg_public_key);
        
        // Compute partial signatures
        let s0 = musig2::partial_sign(
            &[p1_partial_nonces.R.clone()],
            p0_partial_nonces.clone(),
            &party0_key_agg,
            &party0_key,
            &message
        );
        let s1 = musig2::partial_sign(
            &[p0_partial_nonces.R],
            p1_partial_nonces.clone(),
            &party1_key_agg,
            &party1_key,
            &message
        );

        let signature0 = musig2::aggregate_partial_signatures(&s0, &[s1.my_partial_s.clone()]);
        let signature1 = musig2::aggregate_partial_signatures(&s1, &[s0.my_partial_s.clone()]);
        assert!(s0.R == s1.R, "Different partial nonce aggregation!");
        assert!(signature0.s == signature1.s);
        
        // debugging asserts
        assert!(s0.my_partial_s + s1.my_partial_s == signature0.s, "TEST1");
        // verify:
        assert!(signature0.verify(&message, &party0_key_agg.agg_public_key).is_ok(), "Verification failed!");
        
        // Verify result against dalek
        assert!(verify_dalek(
            &party0_key_agg.agg_public_key,
            &signature0,
            &message
        ), "Dalek signature verification failed!");
    }

}
//     #[test]
//     fn test_multiparty_signing_for_two_parties() {
//         let mut rng = deterministic_fast_rand("test_multiparty_signing_for_two_parties", None);
//         for _i in 0..128 {
//             test_multiparty_signing_for_two_parties_internal(&mut rng);
//         }
//     }

//     fn test_multiparty_signing_for_two_parties_internal(rng: &mut impl Rng) {
//         let message: [u8; 4] = [79, 77, 69, 82];

//         // round 0: generate signing keys
//         let party1_key = ExpandedKeyPair::create();
//         let party2_key = ExpandedKeyPair::create();

//         // round 1: send commitments to ephemeral public keys
//         let (party1_ephemeral_key, party1_sign_first_message, party1_sign_second_message) =
//             aggsig::create_ephemeral_key_and_commit_rng(&party1_key, &message, rng);
//         let (party2_ephemeral_key, party2_sign_first_message, party2_sign_second_message) =
//             aggsig::create_ephemeral_key_and_commit_rng(&party2_key, &message, rng);

//         let party1_commitment = &party1_sign_first_message.commitment;
//         let party2_commitment = &party2_sign_first_message.commitment;

//         // round 2: send ephemeral public keys and check commitments
//         assert!(test_com(
//             &party2_sign_second_message.R,
//             &party2_sign_second_message.blind_factor,
//             party2_commitment
//         ));
//         assert!(test_com(
//             &party1_sign_second_message.R,
//             &party1_sign_second_message.blind_factor,
//             party1_commitment
//         ));

//         // compute apk:
//         let pks = [party1_key.public_key.clone(), party2_key.public_key.clone()];
//         let party1_key_agg = KeyAgg::key_aggregation_n(&pks, 0);
//         let party2_key_agg = KeyAgg::key_aggregation_n(&pks, 1);
//         assert_eq!(party1_key_agg.apk, party2_key_agg.apk);
//         // compute R' = sum(Ri):
//         let Ri = [party1_ephemeral_key.R, party2_ephemeral_key.R];
//         // each party i should run this:
//         let R_tot = aggsig::get_R_tot(&Ri);
//         let s1 = aggsig::partial_sign(
//             &party1_ephemeral_key.r,
//             &party1_key,
//             &party1_key_agg.hash,
//             &R_tot,
//             &party1_key_agg.apk,
//             &message,
//         );
//         let s2 = aggsig::partial_sign(
//             &party2_ephemeral_key.r,
//             &party2_key,
//             &party2_key_agg.hash,
//             &R_tot,
//             &party2_key_agg.apk,
//             &message,
//         );

//         let s = [s1, s2];
//         let signature = aggsig::add_signature_parts(&s);

//         // verify:
//         assert!(signature.verify(&message, &party1_key_agg.apk).is_ok())
//     }

//     #[test]
//     fn test_multiparty_signing_for_three_parties() {
//         let mut rng = deterministic_fast_rand("test_multiparty_signing_for_three_parties", None);
//         for _i in 0..128 {
//             test_multiparty_signing_for_three_parties_internal(&mut rng);
//         }
//     }

//     fn test_multiparty_signing_for_three_parties_internal(rng: &mut impl Rng) {
//         let message: [u8; 4] = [79, 77, 69, 82];

//         // round 0: generate signing keys
//         let party1_key = ExpandedKeyPair::create();
//         let party2_key = ExpandedKeyPair::create();
//         let party3_key = ExpandedKeyPair::create();

//         // round 1: send commitments to ephemeral public keys
//         let (party1_ephemeral_key, party1_sign_first_message, party1_sign_second_message) =
//             aggsig::create_ephemeral_key_and_commit_rng(&party1_key, &message, rng);
//         let (party2_ephemeral_key, party2_sign_first_message, party2_sign_second_message) =
//             aggsig::create_ephemeral_key_and_commit_rng(&party2_key, &message, rng);
//         let (party3_ephemeral_key, party3_sign_first_message, party3_sign_second_message) =
//             aggsig::create_ephemeral_key_and_commit_rng(&party3_key, &message, rng);

//         let party1_commitment = &party1_sign_first_message.commitment;
//         let party2_commitment = &party2_sign_first_message.commitment;
//         let party3_commitment = &party3_sign_first_message.commitment;

//         // round 2: send ephemeral public keys and check commitments
//         assert!(test_com(
//             &party2_sign_second_message.R,
//             &party2_sign_second_message.blind_factor,
//             party2_commitment
//         ));
//         assert!(test_com(
//             &party1_sign_second_message.R,
//             &party1_sign_second_message.blind_factor,
//             party1_commitment
//         ));
//         assert!(test_com(
//             &party3_sign_second_message.R,
//             &party3_sign_second_message.blind_factor,
//             party3_commitment
//         ));

//         // compute apk:
//         let pks = [
//             party1_key.public_key.clone(),
//             party2_key.public_key.clone(),
//             party3_key.public_key.clone(),
//         ];
//         let party1_key_agg = KeyAgg::key_aggregation_n(&pks, 0);
//         let party2_key_agg = KeyAgg::key_aggregation_n(&pks, 1);
//         let party3_key_agg = KeyAgg::key_aggregation_n(&pks, 2);
//         assert_eq!(party1_key_agg.apk, party2_key_agg.apk);
//         assert_eq!(party1_key_agg.apk, party3_key_agg.apk);
//         // compute R' = sum(Ri):
//         let Ri = [
//             party1_ephemeral_key.R,
//             party2_ephemeral_key.R,
//             party3_ephemeral_key.R,
//         ];
//         // each party i should run this:
//         let R_tot = aggsig::get_R_tot(&Ri);
//         let s1 = aggsig::partial_sign(
//             &party1_ephemeral_key.r,
//             &party1_key,
//             &party1_key_agg.hash,
//             &R_tot,
//             &party1_key_agg.apk,
//             &message,
//         );
//         let s2 = aggsig::partial_sign(
//             &party2_ephemeral_key.r,
//             &party2_key,
//             &party2_key_agg.hash,
//             &R_tot,
//             &party2_key_agg.apk,
//             &message,
//         );
//         let s3 = aggsig::partial_sign(
//             &party3_ephemeral_key.r,
//             &party3_key,
//             &party3_key_agg.hash,
//             &R_tot,
//             &party3_key_agg.apk,
//             &message,
//         );

//         let s = [s1, s2, s3];
//         let signature = aggsig::add_signature_parts(&s);

//         // verify:
//         assert!(signature.verify(&message, &party1_key_agg.apk).is_ok())
//     }

//     #[test]
//     fn test_verify_standard_sig() {
//         // msg hash:05b5d2c43079b8d696ebb21f6e1d1feb7c4aa7c5ba47eea4940f549ebb212e3d
//         // sk: ab2add54327c0baa15d21961f820d8fa231de60450dadd7ce2dec12a9934dddc3b97c9279bbb4b501b84d7c3506d5f018a1e1df1d86daab5e97d888af44887eb
//         // pk: 3b97c9279bbb4b501b84d7c3506d5f018a1e1df1d86daab5e97d888af44887eb
//         // sig: 311b4390d1d92ee3c56d66e22c7cacf13fba86c44b61769b81aa26680af02d1b5a180452743fac943b53728e4cbea288a566ba49f7695808d53b3f9f1cd6ed02
//         // R = 311b4390d1d92ee3c56d66e22c7cacf13fba86c44b61769b81aa26680af02d1b
//         // s = 5a180452743fac943b53728e4cbea288a566ba49f7695808d53b3f9f1cd6ed02

//         let msg_str = "05b5d2c43079b8d696ebb21f6e1d1feb7c4aa7c5ba47eea4940f549ebb212e3d";
//         let message = decode(msg_str).unwrap();

//         let pk_str = "3b97c9279bbb4b501b84d7c3506d5f018a1e1df1d86daab5e97d888af44887eb";
//         let pk_dec = decode(pk_str).unwrap();
//         let pk = Point::from_bytes(&pk_dec[..]).unwrap();

//         let R_str = "311b4390d1d92ee3c56d66e22c7cacf13fba86c44b61769b81aa26680af02d1b";
//         let R_dec = decode(R_str).unwrap();
//         let R = Point::from_bytes(&R_dec[..]).unwrap();

//         let s_str = "5a180452743fac943b53728e4cbea288a566ba49f7695808d53b3f9f1cd6ed02";
//         let mut s_dec = decode(s_str).unwrap();
//         s_dec.reverse();
//         let s_bn = BigInt::from_bytes(&s_dec[..]);
//         let s = Scalar::from(&s_bn);

//         let sig = Signature { R, s }; // TODO: with ed25119 signature
//         assert!(sig.verify(&message, &pk).is_ok())
//     }
// }
