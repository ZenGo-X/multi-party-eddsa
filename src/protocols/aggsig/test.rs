/*
    Multisig ed25519

    Copyright 2018 by Kzen Networks

    This file is part of Multisig Schnorr library
    (https://github.com/KZen-networks/multisig-schnorr)

    Multisig Schnorr is free software: you can redistribute
    it and/or modify it under the terms of the GNU General Public
    License as published by the Free Software Foundation, either
    version 3 of the License, or (at your option) any later version.

    @license GPL-3.0+ <https://github.com/KZen-networks/multi-party-ed25519/blob/master/LICENSE>
*/

#[cfg(test)]
mod tests {
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
        let message: [u8; 4] = [79, 77, 69, 82];

        // round 0: generate signing keys
        let party1_key = KeyPair::create();
        let party2_key = KeyPair::create();

        // round 1: send commitments to ephemeral public keys
        let party1_ephemeral_key =
            Signature::create_ephemeral_key_and_commit(&party1_key, &message);
        let party2_ephemeral_key =
            Signature::create_ephemeral_key_and_commit(&party2_key, &message);

        let party1_commitment = &party1_ephemeral_key.commitment;
        let party2_commitment = &party2_ephemeral_key.commitment;

        // round 2: send ephemeral public keys and check commitments
        assert!(test_com(
            &party2_ephemeral_key.R,
            &party2_ephemeral_key.blind_factor,
            party2_commitment
        ));
        assert!(test_com(
            &party1_ephemeral_key.R,
            &party1_ephemeral_key.blind_factor,
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
        let message: [u8; 4] = [79, 77, 69, 82];

        // round 0: generate signing keys
        let party1_key = KeyPair::create();
        let party2_key = KeyPair::create();
        let party3_key = KeyPair::create();

        // round 1: send commitments to ephemeral public keys
        let party1_ephemeral_key =
            Signature::create_ephemeral_key_and_commit(&party1_key, &message);
        let party2_ephemeral_key =
            Signature::create_ephemeral_key_and_commit(&party2_key, &message);
        let party3_ephemeral_key =
            Signature::create_ephemeral_key_and_commit(&party3_key, &message);

        let party1_commitment = &party1_ephemeral_key.commitment;
        let party2_commitment = &party2_ephemeral_key.commitment;
        let party3_commitment = &party3_ephemeral_key.commitment;

        // round 2: send ephemeral public keys and check commitments
        assert!(test_com(
            &party2_ephemeral_key.R,
            &party2_ephemeral_key.blind_factor,
            party2_commitment
        ));
        assert!(test_com(
            &party1_ephemeral_key.R,
            &party1_ephemeral_key.blind_factor,
            party1_commitment
        ));
        assert!(test_com(
            &party3_ephemeral_key.R,
            &party3_ephemeral_key.blind_factor,
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
}
