# zcash-devtool

This repository contains a CLI app for working with Zcash transactions and the
Zcash blockchain, including stateless Zcash wallet functionality based upon the
`zcash_client_backend` and `zcash_client_sqlite` crates. It is built by
developers, for developers for use in prototyping Zcash functionality, and
should not be considered production-ready. The command-line API that this tool
exposes can and will change at any time and without warning.

## Security Warnings

**DO NOT USE THIS IN PRODUCTION!!!**

This app has not been written with security in mind. It does however have affordances
such as encryption of the mnemonic seed phrases that should make it viable for small
scale experimentation, at your own risk.

### Wallet encryption

By default, the mnemonic seed phrase is encrypted to an [age](https://age-encryption.org/)
identity file (the `-i` parameter), but the wallet database (`data.sqlite`), which contains
your accounts, addresses, notes, and full transaction history, is stored **unencrypted**.

Passing `--encrypt-data` at `init` instead protects the wallet with a **password**:

- `data.sqlite` is encrypted with [SQLCipher](https://www.zetetic.net/sqlcipher/) (AES-256),
  keyed from the password via PBKDF2.
- The mnemonic seed is encrypted to the same password (no identity file is used or needed).
- The public block cache (`blockmeta.sqlite` and the `blocks/` directory) is left
  unencrypted, as it contains only public chain data.

You will be prompted for the password on each command that needs to open the wallet or use
the seed. For scripting, the password may be supplied via the `ZCASH_WALLET_PASSWORD`
environment variable (note that this exposes it to the process environment). Wallets created
without `--encrypt-data` continue to behave exactly as before.

## Usage

No binary artifacts are provided for this crate; it is generally used via
`cargo run` as follows:

To obtain the help docs:
```
cargo run --release -- --help
```
To obtain the help for a specific command (in this case, `init`)
```
cargo run --release -- --help init
```

To create a new empty testnet wallet:
```
cargo run --release -- wallet -w <wallet_dir> init --name "<account_name>" -i <identity_file> -n test
cargo run --release -- wallet -w <wallet_dir> sync
```

Note: The `-i` (identity) parameter specifies an age identity file for encrypting the mnemonic phrase. The file will be generated if it doesn't exist.

Alternatively, to create a password-encrypted wallet (encrypting both `data.sqlite` and the
seed; no identity file needed):
```
cargo run --release -- wallet -w <wallet_dir> init --name "<account_name>" --encrypt-data -n test
cargo run --release -- wallet -w <wallet_dir> sync
```
You will be prompted to set a password, and prompted for it again on subsequent commands.

See the help docs for `init` for additional information, including for how to
initialize a mainnet wallet. Initializing a mainnet wallet will require
specifying a mainnet lightwallet server, e.g.
```
cargo run --release -- wallet -w <wallet_dir> init --name "<account_name>" -i <identity_file> -n main -s zecrocks
cargo run --release -- wallet -w <wallet_dir> sync -s zecrocks
```

Whenever you update the `zcash_client_sqlite` dependency, in order to run
necessary migrations:
```
cargo run --release -- wallet -w <wallet_dir> upgrade
```

If you want to run with debug or trace logging:
```
RUST_LOG=debug cargo run --release -- wallet -w <wallet_dir> <command>
```
### Video tutorial of Zcash Devtool
Kris Nuttycombe (@nuttycom) presented this tool during ZconVI. The session is available
on Youtube [here](https://www.youtube.com/watch?v=5gvQF5oFT8E)

[![Youtube preview of the ZconVI presentation Zcash-devtool: the Zcash development multitool](https://img.youtube.com/vi/5gvQF5oFT8E/0.jpg)](https://www.youtube.com/watch?v=5gvQF5oFT8E)

The code developed in this demo resulted in [this](https://github.com/zcash/zcash-devtool/pull/86) pull request.

## Documentation

For a step-by-step guide for how to get started using these tools, see [this
walkthrough](doc/walkthrough.md).

## License

All code in this workspace is licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
