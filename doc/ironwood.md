# Ironwood (NU7) support

This fork of `zcash-devtool` is built to fund and exercise the **Zcash Ironwood**
upgrade (NU7 / V6 transactions). It is used as the *funder* in an end-to-end
harness: it talks to `lightwalletd` over gRPC, and must be able to **create** an
Ironwood-value transaction so downstream components can receive Ironwood funds.

## What changed in this repo

1. **Dependencies repointed to the Valar Group fork.**
   `Cargo.toml` adds a `[patch.crates-io]` section that redirects every
   `librustzcash` crate this tool uses to
   [`valargroup/librustzcash`](https://github.com/valargroup/librustzcash) at rev
   `5df7f06486c7c1cab317a069809b7147857e37ee` (branch `ironwood-integration`),
   and `orchard` to [`zcash/orchard`](https://github.com/zcash/orchard) at rev
   `0eaea4ebb5aa4ba2b6cf4afa0e1c9b5e8c03273a` — the exact revision the fork
   itself depends on, so there is a single `orchard` in the graph. The fork
   keeps the same crate versions as crates.io, so these are semver-compatible
   source replacements that also cover transitive uses.

2. **Ironwood feature gate enabled for all builds.**
   `.cargo/config.toml` sets `--cfg zcash_unstable="nu6.3"` via `build.rustflags`.
   The fork gates all Ironwood code behind `cfg(zcash_unstable = "nu6.3")`, so
   this flag must be present for the Ironwood APIs (and this tool's migration
   command) to compile in. No extra environment variable is required —
   `cargo build`/`cargo run` in this directory pick the flag up automatically.

3. **New command: `wallet migrate-to-ironwood`.**
   Wraps `zcash_client_backend`'s `create_orchard_to_ironwood_transaction`. It
   spends Orchard notes from an account and creates a single Ironwood (V6) output
   to that account's internal Orchard receiver, migrating the full selected
   Orchard value minus fees (no Orchard change). The signed transaction is then
   transmitted to `lightwalletd` exactly like `wallet shield`/`wallet send`.

   ```
   cargo run --release -- wallet -w <wallet_dir> migrate-to-ironwood \
       [ACCOUNT_UUID] --amount <zatoshis> --identity <age-identity-file>
   ```

   `--amount` is the *minimum* Orchard value to select; the resulting
   transaction migrates the full selected value minus fees.

### Funding flow with Ironwood — `wallet send` already does it

The pre-Ironwood funder flow is all Orchard, through `lightwalletd`:

1. derive a transparent address offline → miner sends transparent coinbase to it;
2. after coinbase maturity, `wallet shield` moves transparent → Orchard;
3. `wallet send` moves Orchard → recipient's UA.

**No new "send to Ironwood" command is needed.** Once NU6.3 is active at the
target height, the high-level path that `wallet send`/`wallet pay` already use
(`propose_transfer` → `create_proposed_transactions` → `build_proposed_transaction`)
automatically emits an **Ironwood (V6) output** to the recipient's Orchard
receiver, with Ironwood change back to the sender. The decision is made by
`zcash_client_backend`'s `orchard_outputs_to_ironwood`, which returns `true`
exactly when `is_nu_active(Nu6_3, target_height)` holds (and a legacy v5 bundle
wasn't explicitly requested via `--version 5`).

So the Ironwood funding step is simply:

```
cargo run --release -- wallet -w <dir> send <zecd_UA> <amount> --identity <id>
```

`wallet migrate-to-ironwood` remains available as an optional Orchard→Ironwood
*self*-migration helper, but it is not the funding mechanism.

### Non-interactive funder commands

The automated funder (harness `Funder` helper) drives the wallet non-interactively
and needs two things the interactive flow doesn't provide. Both are ported from
the `zecrocks/zcash-devtool` `claude/sleepy-faraday-T6HUy` branch so the existing
`Funder` works unchanged:

- **`wallet init --mnemonic <phrase>`** — initialise from a known seed without the
  interactive `rpassword` TTY prompt. If `--mnemonic` is omitted the prompt is
  still used.
- **`wallet derive-address --network <n> --mnemonic <phrase>`** — *offline*
  derivation (no wallet dir, no server) of the account's default addresses,
  printing:

  ```
  Unified Address: <ua>
  Transparent Address: <t-addr>
  ```

  This lets the harness learn the funder's transparent address *before* the chain
  exists (zebra mines coinbase to it as `miner_address`). The transparent address
  is the first account's default receiver — exactly what `create_account`
  produces and what `wallet shield` later scans, so coinbase mined to it is
  detected. (Mnemonics passed on the command line are visible in the process
  list; this is for ephemeral test wallets only.)

### Network activation is the real gate — use `--network regtest`

`is_nu_active(Nu6_3, …)` is only `true` if the wallet's *params* schedule NU6.3.
On `consensus::Network::{MainNetwork, TestNetwork}` the fork hardcodes
`Nu6_3 => None`, so on those networks `wallet send` will never route to Ironwood.
Ironwood funding therefore requires running the wallet on a **regtest /
local-consensus** network, added here as `--network regtest` (see
`src/network.rs`). Because regtest has no hosted lightwalletd, pass an explicit
`--server <host:port>`.

**Cross-component invariant — activation heights must match.** devtool's regtest
schedule (`src/network.rs::regtest_params`) must be identical to zebra's
`configured_activation_heights` and zecd's `regtest()`, or the consensus branch
IDs diverge and transactions are rejected. The agreed schedule:

| Upgrade | Height |
|---|---|
| Overwinter … NU5, NU6 | 1 |
| NU6.1, NU6.2 | 4 |
| NU6.3 (Ironwood) | 8 |

## Companion Docker images (harness, not this repo)

The funder is a `lightwalletd` gRPC client, and `lightwalletd` follows a Zebra
node. Both must understand Ironwood/V6 for the end-to-end flow. The harness
extracts stock `zebrad` + `lightwalletd` images today; for Ironwood, build and
publish these two and point the harness at them:

| Image | Build from | Pin | Replaces |
|-------|-----------|-----|----------|
| zebra (Ironwood) | `valargroup/zebra` branch `add-ironwood-v6-value-pool` | `c319f8296be4871f2f2deb1d454d508d3cea5cba` | `zfnd/zebra:5.0.0` |
| lightwalletd (V6 parser) | `valargroup/lightwalletd` branch `adam/lightwalletd-nu7-v6-parser` | `360a37d588756b2fc96c3e4403296cd2b47dbc04` | stock `electriccoinco/lightwalletd` |

> **Branch-naming trap:** on both `zebra` and `lightwalletd`, the `ironwood-main`
> branch does **not** yet carry the Ironwood feature work — use the branches/pins
> above. Switch to `ironwood-main` only once that work merges down.
