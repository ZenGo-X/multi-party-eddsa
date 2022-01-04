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
    use curv::arithmetic::Converter;
    use hex::decode;
    use rand::{Rng, RngCore};
    use std::convert::TryInto;

    use protocols::tests::deterministic_fast_rand;
    use protocols::{
        musig2::{self, PublicKeyAgg},
        tests::verify_dalek,
        ExpandedKeyPair,
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

        let mut msg = [0u8; 36];
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
                let agg_pub_keys: Vec<_> = pubkeys_list
                    .iter()
                    .map(|pubkey| PublicKeyAgg::key_aggregation_n(pubkeys_list.clone(), pubkey))
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
                            &agg_pub_keys[index],
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
                assert!(
                    signatures[0]
                        .verify(msg, &agg_pub_keys[0].agg_public_key)
                        .is_ok(),
                    "Signature verification failed!"
                );

                // Verify result against dalek
                assert!(
                    verify_dalek(&agg_pub_keys[0].agg_public_key, &signatures[0], msg),
                    "Dalek signature verification failed!"
                );
            }
        }
    }

    #[test]
    fn test_multiparty_signing_for_two_parties() {
        let mut rng = deterministic_fast_rand("test_multiparty_signing_for_two_parties", None);
        for _i in 0..100 {
            test_multiparty_signing_for_two_parties_internal(&mut rng);
        }
    }

    fn test_multiparty_signing_for_two_parties_internal(rng: &mut impl Rng) {
        let message: [u8; 12] = [79, 77, 69, 82, 60, 61, 100, 156, 109, 125, 3, 19];

        // round 0: generate signing keys generate nonces
        let party0_key = ExpandedKeyPair::create();
        let party1_key = ExpandedKeyPair::create();

        let p0_partial_nonces =
            musig2::generate_partial_nonces(&party0_key, Option::Some(&message), rng);
        let p1_partial_nonces =
            musig2::generate_partial_nonces(&party1_key, Option::Some(&message), rng);

        // compute aggregated public key:
        let pks = vec![party0_key.public_key.clone(), party1_key.public_key.clone()];
        let party0_key_agg = PublicKeyAgg::key_aggregation_n(pks.clone(), &party0_key.public_key);
        let party1_key_agg = PublicKeyAgg::key_aggregation_n(pks, &party1_key.public_key);
        assert_eq!(party0_key_agg.agg_public_key, party1_key_agg.agg_public_key);
        // Compute partial signatures
        let s0 = musig2::partial_sign(
            &[p1_partial_nonces.R.clone()],
            p0_partial_nonces.clone(),
            &party0_key_agg,
            &party0_key,
            &message,
        );
        let s1 = musig2::partial_sign(
            &[p0_partial_nonces.R],
            p1_partial_nonces,
            &party1_key_agg,
            &party1_key,
            &message,
        );

        let signature0 = musig2::aggregate_partial_signatures(&s0, &[s1.my_partial_s.clone()]);
        let signature1 = musig2::aggregate_partial_signatures(&s1, &[s0.my_partial_s.clone()]);
        assert!(s0.R == s1.R, "Different partial nonce aggregation!");
        assert!(signature0.s == signature1.s);
        // debugging asserts
        assert!(s0.my_partial_s + s1.my_partial_s == signature0.s, "TEST1");
        // verify:
        assert!(
            signature0
                .verify(&message, &party0_key_agg.agg_public_key)
                .is_ok(),
            "Verification failed!"
        );
        // Verify result against dalek
        assert!(
            verify_dalek(&party0_key_agg.agg_public_key, &signature0, &message),
            "Dalek signature verification failed!"
        );
    }
}
