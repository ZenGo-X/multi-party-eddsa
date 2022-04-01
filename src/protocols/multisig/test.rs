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
#[cfg(test)]
mod tests {

    use curv::arithmetic::Converter;
    use curv::cryptographic_primitives::hashing::merkle_tree::MT256;
    use curv::cryptographic_primitives::hashing::DigestExt;
    use curv::elliptic::curves::Scalar;
    use curv::BigInt;
    use protocols::multisig::{partial_sign, verify, EphKey, Keys, Signature};
    use sha2::{digest::Digest, Sha256};

    #[test]
    fn two_party_key_gen() {
        for _i in 0..256 {
            two_party_key_gen_internal();
        }
    }

    fn two_party_key_gen_internal() {
        let message_vec = vec![79, 77, 69, 82];
        let message_bn = BigInt::from_bytes(&message_vec[..]);
        let message = Sha256::new().chain_bigint(&message_bn).result_bigint();

        // party1 key gen:
        let keys_1 = Keys::create();

        keys_1.clone().I.update_key_pair(Scalar::zero());

        let broadcast1 = Keys::broadcast(keys_1.clone());
        // party2 key gen:
        let keys_2 = Keys::create();
        let broadcast2 = Keys::broadcast(keys_2.clone());
        let ix_vec = vec![broadcast1, broadcast2];
        let e = Keys::collect_and_compute_challenge(&ix_vec);

        let y1 = partial_sign(&keys_1, e.clone());
        let y2 = partial_sign(&keys_2, e.clone());
        let sig1 = Signature::set_signature(&keys_1.X.public_key, &y1);
        let sig2 = Signature::set_signature(&keys_2.X.public_key, &y2);
        // partial verify
        assert!(verify(&keys_1.I.public_key, &sig1, &e).is_ok());
        assert!(verify(&keys_2.I.public_key, &sig2, &e).is_ok());

        // merkle tree (in case needed)

        let ge_vec = vec![(keys_1.I.public_key).clone(), (keys_2.I.public_key).clone()];
        let mt256 = MT256::<_, Sha256>::create_tree(ge_vec);
        let proof1 = mt256.build_proof(keys_1.I.public_key.clone()).unwrap();
        let proof2 = mt256.build_proof(keys_2.I.public_key.clone()).unwrap();
        let root = mt256.get_root();

        //TODO: reduce number of clones.
        // signing
        let party1_com = EphKey::gen_commit(&keys_1.I, &message);

        let party2_com = EphKey::gen_commit(&keys_2.I, &message);

        let eph_pub_key_vec = vec![
            party1_com.eph_key_pair.public_key.clone(),
            party2_com.eph_key_pair.public_key.clone(),
        ];
        let pub_key_vec = vec![keys_1.I.public_key.clone(), keys_2.I.public_key.clone()];

        let (It, Xt, es) = EphKey::compute_joint_comm_e(pub_key_vec, eph_pub_key_vec, &message);

        let y1 = party1_com.partial_sign(&keys_1.I, es.clone());
        let y2 = party2_com.partial_sign(&keys_2.I, es.clone());
        let y = EphKey::add_signature_parts(vec![y1, y2]);
        let sig = Signature::set_signature(&Xt, &y);
        assert!(verify(&It, &sig, &es).is_ok());

        assert!(proof1.verify(&root).is_ok());
        assert!(proof2.verify(&root).is_ok());
    }
}
