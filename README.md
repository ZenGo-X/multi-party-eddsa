
# Multi Party EdDSA signatures
Rust implementation of multiparty Ed25519 signature scheme.

#### Currently supporting:
* [Aggregated Signatures](https://github.com/KZen-networks/multi-party-ed25519/wiki/Aggregated-Ed25519-Signatures)
* [Accountable-Subgroup Multisignatures](https://github.com/KZen-networks/multi-party-schnorr/blob/master/papers/accountable_subgroups_multisignatures.pdf).
* Threshold EdDSA scheme based on [provably secure distributed schnorr signatures and a {t,n} threshold scheme](https://github.com/KZen-networks/multi-party-schnorr/blob/master/papers/provably_secure_distributed_schnorr_signatures_and_a_threshold_scheme.pdf). For more efficient implementation we used the DKG from [Fast Multiparty Threshold ECDSA with Fast Trustless Setup](https://eprint.iacr.org/2019/114.pdf). The cost is robustness: if there is a malicious party out of the n parties in DKG the protocol stops and if there is a malicious party out of the t parties used for signing the signature protocol will stop.

The above protocols are for Schnorr signature system. EdDSA is a variant of Schnorr signature system with (possibly twisted) Edwards curves. We adopt the multi party implementations to follow Ed25519 methods for private key and public key generation according to [RFC8032](https://tools.ietf.org/html/rfc8032#section-5.1) 

## Run GG18 Demo

The following steps are for setup, key generation with `n` parties and signing with `t+1` parties.

### Setup

1.  We use shared state machine architecture (see [white city](https://github.com/KZen-networks/white-city)). The parameters `parties` and `threshold` can be configured by changing the file: `param.json`. A keygen will run with `parties` parties and signing will run with any subset of `threshold + 1` parties. `param.json` file should be located in the same path of the client software.

2.  Install [Rust](https://rustup.rs/). Run `cargo build --release --examples` (it will build into `/target/release/examples/`)

3.  Run the shared state machine: `./sm_manager`. By default, it's configured to be in `127.0.0.1:8000`, this can be changed in `Rocket.toml` file. The `Rocket.toml` file should be in the same folder you run `sm_manager` from.

### KeyGen

run `gg18_keygen_client` as follows: `./gg18_keygen_client http://127.0.0.1:8000 keys.store`. Replace IP and port with the ones configured in setup. Once `n` parties join the application will run till finish. At the end each party will get a local keys file `keys.store` (change filename in command line). This contains secret and public data of the party after keygen. The file therefore should remain private.

### Sign

Run `./sign_client`. The application takes three arguments: `IP:port` as in keygen, `filename` and message to be signed: `./sign_client http://127.0.0.1:8001 keys.store "KZen Networks"`. The same message should be used by all signers. Once `t+1` parties join the protocol will run and will output to screen signature (R,s).

The `./sign_client` executable initially tries to unhex its input message (the third parameter). Before running ensure two things:

1. If you want to pass a binary message to be signed - hex it.
2. If you want to pass a textual message in a non-hex form, make sure it can't be unhexed.
   Simply put, the safest way to use the signing binary is to just always hex your messages before passing them to the `./sign_client` executable.

#### Example
To sign the message `hello world`, first calculate its hexadecimal representation. This yields the `68656c6c6f20776f726c64`.
Then, run:
```bash
./sign_client http://127.0.0.1:8000 keys.store "68656c6c6f20776f726c64"
```


License
-------
This library is released under the terms of the GPL-3.0 license. See [LICENSE](LICENSE) for more information.

Development Process
-------------------
The contribution workflow is described in [CONTRIBUTING.md](CONTRIBUTING.md).

Contact
-------------------
Feel free to [reach out](mailto:github@kzencorp.com) or join the ZenGo X [Telegram](https://t.me/joinchat/ET1mddGXRoyCxZ-7) for discussions on code and research.
