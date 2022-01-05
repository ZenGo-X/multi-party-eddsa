#![allow(non_snake_case)]

use curv::{
    arithmetic::traits::*,
    cryptographic_primitives::{
        secret_sharing::feldman_vss::VerifiableSS,
    },
    BigInt,
};

use multi_party_eddsa::protocols::thresholdsig::{SharedKeys};

use reqwest::Client;
use std::{env, fs, time};
use std::time::Duration;
use curv::elliptic::curves::{Ed25519, Point, Scalar};

mod common;
use common::{
    broadcast, poll_for_broadcasts, poll_for_p2p, postb, sendp2p, Params, PartySignup,
};
use multi_party_eddsa::protocols::{Signature, thresholdsig};
use multi_party_eddsa::protocols::thresholdsig::{EphemeralKey, EphemeralSharedKeys, Parameters, Keys, KeyGenBroadcastMessage1, LocalSig};
use crate::common::{AEAD, aes_decrypt, aes_encrypt, AES_KEY_BYTES_LEN};

#[allow(clippy::cognitive_complexity)]
fn main() {
    if env::args().nth(4).is_some() {
        panic!("too many arguments")
    }
    if env::args().nth(3).is_none() {
        panic!("too few arguments")
    }
    let message_str = env::args().nth(3).unwrap_or_else(|| "".to_string());
    // read key file
    let key_file_path = env::args().nth(2).unwrap();

    //read parameters:
    let data = fs::read_to_string("params.json")
        .expect("Unable to read params, make sure config file is present in the same folder ");
    let params: Params = serde_json::from_str(&data).unwrap();

    let (signature, y_sum) = run_signer(key_file_path, params, message_str);
    let sign_json = serde_json::json!({
        "r": (BigInt::from_bytes(&(signature.R).to_bytes(false))).to_str_radix(16),
        "s": (BigInt::from_bytes(&(signature.s).to_bytes())).to_str_radix(16),
        "y": y_sum
    });
    let sign_json = serde_json::to_string(&sign_json).unwrap();

    /*let sign_json = serde_json::to_string(&(
        "r",
        (BigInt::from_bytes(&(signature.R).to_bytes(false))).to_str_radix(16),
        "s",
        (BigInt::from_bytes(&(signature.s).to_bytes())).to_str_radix(16),
    ))
    .unwrap();*/

    fs::write("signature.json".to_string(), sign_json.clone()).expect("Unable to save !");

    println!("{:?}", sign_json);
}

fn run_signer(key_file_path: String, params: Params, message_str:String) -> (Signature, Point<Ed25519>) {
    ///
    /// This function is written inspired from the
    /// test function: protocols::thresholdsig::test::tests::test_t2_n5_sign_with_4_internal()
    //TODO Make sure this approach is valid for {t,n} multy party threshold EdDSA
    let message = match hex::decode(message_str.clone()) {
        Ok(x) => x,
        Err(_e) => message_str.as_bytes().to_vec(),
    };
    let message = &message[..];
    let client = Client::new();
    // delay:
    let delay = time::Duration::from_millis(25);

    let data = fs::read_to_string(key_file_path)
        .expect("Unable to load keys, did you run keygen first? ");
    let (party_keys, shared_keys, _, vss_scheme_vec, Y): (
        Keys,
        SharedKeys,
        u16,
        Vec<VerifiableSS<Ed25519>>,
        //Vec<EncryptionKey>,
        Point<Ed25519>,
    ) = serde_json::from_str(&data).unwrap();

    let THRESHOLD = params.threshold.parse::<u16>().unwrap();
    let PARTIES = params.parties.parse::<u16>().unwrap();
    //signup:
    let (party_num_int, uuid) = match signup(&client).unwrap() {
        PartySignup { number, uuid } => (number, uuid),
    };
    println!("number: {:?}, uuid: {:?}", party_num_int, uuid);

    let (_eph_keys_vec, eph_shared_keys_vec, R, eph_vss_vec) = eph_keygen_t_n_parties(
        client.clone(),
        uuid.clone(),
        delay,
        THRESHOLD.clone(),
        PARTIES,
        party_num_int,
        &party_keys,
        &message,
    );

    let local_sig = LocalSig::compute(
        &message,
        &eph_shared_keys_vec[(party_num_int-1) as usize],
        &shared_keys,
    );

    let local_sig_vec = exchange_data(
        client.clone(),
        party_num_int,
        PARTIES,
        uuid,
        "round1_local_sig",
        delay,
        local_sig
    );

    let parties_index_vec = (0..PARTIES)
        .map(|i| i as u16)
        .collect::<Vec<u16>>();

    let verify_local_sig = LocalSig::verify_local_sigs(
        &local_sig_vec,
        &parties_index_vec.as_slice(),
        &vss_scheme_vec,
        &eph_vss_vec,
    );

    assert!(verify_local_sig.is_ok());

    let vss_sum_local_sigs = verify_local_sig.unwrap();

    // each party / dealer can generate the signature
    let signature =
        thresholdsig::generate(&vss_sum_local_sigs, &local_sig_vec, &parties_index_vec, R);
    let verify_sig = signature.verify(&message, &Y);
    assert!(verify_sig.is_ok());

    (signature, Y)
}


pub fn eph_keygen_t_n_parties(
    client: Client,
    uuid: String,
    delay: Duration,
    t: u16, // system threshold
    n: u16, // number of signers
    party_num_int: u16,
    key_i: &Keys,
    message: &[u8],
) -> (
    EphemeralKey,
    Vec<EphemeralSharedKeys>,
    Point<Ed25519>,
    Vec<VerifiableSS<Ed25519>>,
) {
    let parties = (0..n)
        .map(|i| (i + 1) as u16)
        .collect::<Vec<u16>>();

    let parames = Parameters {
        threshold: t,
        share_count: n.clone(),
    };
    assert!(parties.len() as u16 > t && parties.len() as u16 <= n);

    let eph_party_key: EphemeralKey = EphemeralKey::ephermeral_key_create_from_deterministic_secret(
        key_i,
        message,
        party_num_int,
    );

    let mut bc1_vec = Vec::new();
    let mut blind_vec = Vec::new();
    let mut R_vec = Vec::new();
    let (bc_i, blind) = eph_party_key.phase1_broadcast();

    assert!(broadcast(
        &client,
        party_num_int,
        "eph_keygen_round1",
        serde_json::to_string(&(bc_i.clone(), blind.clone(), eph_party_key.R_i.clone())).unwrap(),
        uuid.clone()
    )
    .is_ok());
    let round1_ans_vec = poll_for_broadcasts(
        &client,
        party_num_int,
        n as u16,
        delay,
        "eph_keygen_round1",
        uuid.clone(),
    );

    let mut j = 0;
    let mut enc_keys: Vec<Vec<u8>> = Vec::new();
    for i in 1..=n {
        if i == party_num_int {
            bc1_vec.push(bc_i.clone());
            blind_vec.push(blind.clone());
            R_vec.push(eph_party_key.R_i.clone());
        } else {
            let (bc1_j, blind_j, R_i_j) = serde_json::from_str::<(KeyGenBroadcastMessage1, BigInt, Point<Ed25519>)>(&round1_ans_vec[j]).unwrap();
            bc1_vec.push(bc1_j);
            blind_vec.push(blind_j);
            R_vec.push(R_i_j.clone());
            let key_bn: BigInt = (R_i_j.clone() * eph_party_key.r_i.clone()).x_coord().unwrap();
            let key_bytes = BigInt::to_bytes(&key_bn);
            let mut template: Vec<u8> = vec![0u8; AES_KEY_BYTES_LEN - key_bytes.len()];
            template.extend_from_slice(&key_bytes[..]);
            enc_keys.push(template);
            j += 1;
        }
    }

    let mut R_vec_iter = R_vec.iter();
    let head = R_vec_iter.next().unwrap();
    let tail = R_vec_iter;
    let R_sum = tail.fold(head.clone(), |acc, x| acc + x);
    let (vss_scheme, secret_shares) = eph_party_key
        .phase1_verify_com_phase2_distribute(
            &parames, &blind_vec, &R_vec, &bc1_vec, parties.as_slice(),
        )
        .expect("invalid key");

    // round 2: send vss commitments
    assert!(broadcast(
        &client,
        party_num_int,
        "eph_keygen_round2",
        serde_json::to_string(&vss_scheme).unwrap(),
        uuid.clone()
    )
    .is_ok());
    let round2_ans_vec = poll_for_broadcasts(
        &client,
        party_num_int,
        n as u16,
        delay,
        "eph_keygen_round2",
        uuid.clone(),
    );

    let mut j = 0;
    let mut vss_scheme_vec: Vec<VerifiableSS<Ed25519>> = Vec::new();
    for i in 1..=n {
        if i == party_num_int {
            vss_scheme_vec.push(vss_scheme.clone());
        } else {
            let vss_scheme_j: VerifiableSS<Ed25519> = serde_json::from_str(&round2_ans_vec[j]).unwrap();

            vss_scheme_vec.push(vss_scheme_j);
            j += 1;
        }
    }

    //////////////////////////////////////////////////////////////////////////////
    //I'm not sure if we need this phase in ephemeral mode or not?
    let mut j = 0;
    for (k, i) in (1..=n).enumerate() {
        if i != party_num_int {
            // prepare encrypted ss for party i:
            let key_i = &enc_keys[j];
            let plaintext = BigInt::to_bytes(&secret_shares[k].to_bigint());
            let aead_pack_i = aes_encrypt(key_i, &plaintext);
            assert!(sendp2p(
                &client,
                party_num_int,
                i as u16,
                "eph_keygen_round3",
                serde_json::to_string(&aead_pack_i).unwrap(),
                uuid.clone()
            )
            .is_ok());
            j += 1;
        }
    }

    let round3_ans_vec = poll_for_p2p(
        &client,
        party_num_int,
        n as u16,
        delay,
        "eph_keygen_round3",
        uuid.clone(),
    );

    let mut j = 0;
    let mut party_shares: Vec<Scalar<Ed25519>> = Vec::new();
    for i in 1..=n {
        if i == party_num_int {
            party_shares.push(secret_shares[(i - 1) as usize].clone());
        } else {
            let aead_pack: AEAD = serde_json::from_str(&round3_ans_vec[j]).unwrap();
            let key_i = &enc_keys[j];
            let out = aes_decrypt(key_i, aead_pack);
            let out_bn = BigInt::from_bytes(&out[..]);
            let out_fe = Scalar::<Ed25519>::from(&out_bn);
            party_shares.push(out_fe);
            j += 1;
        }
    }
    //////////////////////////////////////////////////////////////////////////////

    let mut shared_keys_vec = Vec::new();
    let eph_shared_key = eph_party_key
        .phase2_verify_vss_construct_keypair(
            &parames,
            &R_vec,
            &party_shares,
            &vss_scheme_vec,
            party_num_int,
        )
        .expect("invalid vss");

    // round 4: send shared key
    assert!(broadcast(
        &client,
        party_num_int,
        "eph_keygen_round4",
        serde_json::to_string(&eph_shared_key).unwrap(),
        uuid.clone()
    )
    .is_ok());
    let round4_ans_vec = poll_for_broadcasts(
        &client,
        party_num_int,
        n as u16,
        delay,
        "eph_keygen_round4",
        uuid.clone(),
    );

    let mut j = 0;
    for i in 1..=n {
        if i == party_num_int {
            shared_keys_vec.push(eph_shared_key.clone());
        } else {
            let shared_key_j:EphemeralSharedKeys = serde_json::from_str(&round4_ans_vec[j]).unwrap();
            shared_keys_vec.push(shared_key_j);
            j += 1;
        }
    }

    (eph_party_key, shared_keys_vec, R_sum, vss_scheme_vec)
}

pub fn signup(client: &Client) -> Result<PartySignup, ()> {
    let key = "signup-sign".to_string();

    let res_body = postb(&client, "signupsign", key).unwrap();
    serde_json::from_str(&res_body).unwrap()
}



pub fn exchange_data<T>(client:Client, party_num:u16, n:u16, uuid:String, round: &str, delay: Duration, data:T) -> Vec<T>
where
    T: Clone + serde::de::DeserializeOwned + serde::Serialize,
{
    assert!(broadcast(
        &client,
        party_num,
        &round,
        serde_json::to_string(&data).unwrap(),
        uuid.clone()
    )
    .is_ok());
    let round_ans_vec = poll_for_broadcasts(
        &client,
        party_num,
        n,
        delay,
        &round,
        uuid.clone(),
    );

    let json_answers = round_ans_vec.clone();
    let mut j = 0;
    let mut answers: Vec<T> = Vec::new();
    for i in 1..=n {
        if i == party_num {
            answers.push(data.clone());
        } else {
            let data_j: T = serde_json::from_str::<T>(&json_answers[j].clone()).unwrap();
            answers.push(data_j);
            j += 1;
        }
    }

    return answers;
}

