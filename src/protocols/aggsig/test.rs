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
    use curv::elliptic::curves::traits::ECPoint;
    use curv::GE;
    use protocols::aggsig::{test_com, verify, KeyPair, Signature};

    #[test]
    fn test_ed25519_one_party() {
        let message: [u8; 4] = [79, 77, 69, 82];
        let party1_keys = KeyPair::create();
        let signature = Signature::sign_single(&message, &party1_keys);
        assert!(verify(&signature, &message, &party1_keys.public_key).is_ok());
    }

    #[test]
    fn test_multiparty_signing_for_two_parties() {
        for _i in 0..256 {
            test_multiparty_signing_for_two_parties_internal();
        }
    }

    fn test_multiparty_signing_for_two_parties_internal() {
        let message: [u8; 4] = [79, 77, 69, 82];

        // round 0: generate signing keys
        let party1_key = KeyPair::create();
        let party2_key = KeyPair::create();

        // round 1: send commitments to ephemeral public keys
        let (party1_ephemeral_key, party1_sign_first_message, party1_sign_second_message) =
            Signature::create_ephemeral_key_and_commit(&party1_key, &message);
        let (party2_ephemeral_key, party2_sign_first_message, party2_sign_second_message) =
            Signature::create_ephemeral_key_and_commit(&party2_key, &message);

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
        let mut pks: Vec<GE> = Vec::new();
        pks.push(party1_key.public_key.clone());
        pks.push(party2_key.public_key.clone());
        let party1_key_agg = KeyPair::key_aggregation_n(&pks, &0);
        let party2_key_agg = KeyPair::key_aggregation_n(&pks, &1);
        assert_eq!(party1_key_agg.apk, party2_key_agg.apk);
        // compute R' = sum(Ri):
        let mut Ri: Vec<GE> = Vec::new();
        Ri.push(party1_ephemeral_key.R.clone());
        Ri.push(party2_ephemeral_key.R.clone());
        // each party i should run this:
        let R_tot = Signature::get_R_tot(Ri);
        let k = Signature::k(&R_tot, &party1_key_agg.apk, &message);
        let s1 = Signature::partial_sign(
            &party1_ephemeral_key.r,
            &party1_key,
            &k,
            &party1_key_agg.hash,
            &R_tot,
        );
        let s2 = Signature::partial_sign(
            &party2_ephemeral_key.r,
            &party2_key,
            &k,
            &party2_key_agg.hash,
            &R_tot,
        );

        let mut s: Vec<Signature> = Vec::new();
        s.push(s1);
        s.push(s2);
        let signature = Signature::add_signature_parts(s);

        // verify:
        assert!(verify(&signature, &message, &party1_key_agg.apk).is_ok())
    }

    #[test]
    fn test_multiparty_signing_for_three_parties() {
        for _i in 0..256 {
            test_multiparty_signing_for_three_parties_internal();
        }
    }

    fn test_multiparty_signing_for_three_parties_internal() {
        let message: [u8; 4] = [79, 77, 69, 82];

        // round 0: generate signing keys
        let party1_key = KeyPair::create();
        let party2_key = KeyPair::create();
        let party3_key = KeyPair::create();

        // round 1: send commitments to ephemeral public keys
        let (party1_ephemeral_key, party1_sign_first_message, party1_sign_second_message) =
            Signature::create_ephemeral_key_and_commit(&party1_key, &message);
        let (party2_ephemeral_key, party2_sign_first_message, party2_sign_second_message) =
            Signature::create_ephemeral_key_and_commit(&party2_key, &message);
        let (party3_ephemeral_key, party3_sign_first_message, party3_sign_second_message) =
            Signature::create_ephemeral_key_and_commit(&party3_key, &message);

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
        let mut pks: Vec<GE> = Vec::new();
        pks.push(party1_key.public_key.clone());
        pks.push(party2_key.public_key.clone());
        pks.push(party3_key.public_key.clone());
        let party1_key_agg = KeyPair::key_aggregation_n(&pks, &0);
        let party2_key_agg = KeyPair::key_aggregation_n(&pks, &1);
        let party3_key_agg = KeyPair::key_aggregation_n(&pks, &2);
        assert_eq!(party1_key_agg.apk, party2_key_agg.apk);
        assert_eq!(party1_key_agg.apk, party3_key_agg.apk);
        // compute R' = sum(Ri):
        let mut Ri: Vec<GE> = Vec::new();
        Ri.push(party1_ephemeral_key.R.clone());
        Ri.push(party2_ephemeral_key.R.clone());
        Ri.push(party3_ephemeral_key.R.clone());
        // each party i should run this:
        let R_tot = Signature::get_R_tot(Ri);
        let k = Signature::k(&R_tot, &party1_key_agg.apk, &message);
        let s1 = Signature::partial_sign(
            &party1_ephemeral_key.r,
            &party1_key,
            &k,
            &party1_key_agg.hash,
            &R_tot,
        );
        let s2 = Signature::partial_sign(
            &party2_ephemeral_key.r,
            &party2_key,
            &k,
            &party2_key_agg.hash,
            &R_tot,
        );
        let s3 = Signature::partial_sign(
            &party3_ephemeral_key.r,
            &party3_key,
            &k,
            &party3_key_agg.hash,
            &R_tot,
        );

        let mut s: Vec<Signature> = Vec::new();
        s.push(s1);
        s.push(s2);
        s.push(s3);
        let signature = Signature::add_signature_parts(s);

        // verify:
        assert!(verify(&signature, &message, &party1_key_agg.apk).is_ok())
    }

    use curv::elliptic::curves::traits::ECScalar;
    use curv::{BigInt, FE};
    use hex::decode;
    #[test]
    fn test_verify_standard_sig() {
        // msg hash:05b5d2c43079b8d696ebb21f6e1d1feb7c4aa7c5ba47eea4940f549ebb212e3d
        // sk: ab2add54327c0baa15d21961f820d8fa231de60450dadd7ce2dec12a9934dddc3b97c9279bbb4b501b84d7c3506d5f018a1e1df1d86daab5e97d888af44887eb
        // pk: 3b97c9279bbb4b501b84d7c3506d5f018a1e1df1d86daab5e97d888af44887eb
        // sig: 311b4390d1d92ee3c56d66e22c7cacf13fba86c44b61769b81aa26680af02d1b5a180452743fac943b53728e4cbea288a566ba49f7695808d53b3f9f1cd6ed02
        // R = 311b4390d1d92ee3c56d66e22c7cacf13fba86c44b61769b81aa26680af02d1b
        // s = 5a180452743fac943b53728e4cbea288a566ba49f7695808d53b3f9f1cd6ed02

        let eight_bn = BigInt::from(8);
        let eight: FE = ECScalar::from(&eight_bn);
        let eight_inv = eight.invert();

        let msg_str = "05b5d2c43079b8d696ebb21f6e1d1feb7c4aa7c5ba47eea4940f549ebb212e3d";
        let message = decode(msg_str).unwrap();

        let pk_str = "3b97c9279bbb4b501b84d7c3506d5f018a1e1df1d86daab5e97d888af44887eb";
        let pk_dec = decode(pk_str).unwrap();
        let pk: GE = ECPoint::from_bytes(&pk_dec[..]).unwrap();
        let pk = pk * eight_inv;

        let R_str = "311b4390d1d92ee3c56d66e22c7cacf13fba86c44b61769b81aa26680af02d1b";
        let R_dec = decode(R_str).unwrap();
        let R: GE = ECPoint::from_bytes(&R_dec[..]).unwrap();
        let R = R * eight_inv;

        let s_str = "5a180452743fac943b53728e4cbea288a566ba49f7695808d53b3f9f1cd6ed02";
        let mut s_dec = decode(s_str).unwrap();
        s_dec.reverse();
        let s_bn = BigInt::from(&s_dec[..]);
        let s: FE = ECScalar::from(&s_bn);

        let sig = Signature { R, s };
        assert!(verify(&sig, &message, &pk).is_ok())
    }
}
