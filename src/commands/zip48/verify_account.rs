use std::fs;
use std::path::PathBuf;

use anyhow::{anyhow, Context};
use clap::Args;
use secrecy::ExposeSecret;
use transparent::zip48;

use crate::config::WalletConfig;

// Options accepted for the `zip48 verify-account` command
#[derive(Debug, Args)]
pub(crate) struct Command {
    /// A file containing the key information vector.
    #[clap(short, long)]
    key_info: PathBuf,

    /// A threshold value indicating the number of signatures required to spend from the
    /// address.
    ///
    /// This should be extracted from the wallet descriptor template. For example, if the
    /// template is `sh(sortedmulti(2,@0/**,@1/**,@2/**))` then `required = 2`.
    #[clap(long)]
    required: u8,

    /// age identity file to decrypt the mnemonic phrase with (unencrypted wallets only)
    #[arg(short, long)]
    identity: Option<String>,
}

impl Command {
    pub(crate) fn run(self, wallet_dir: Option<String>) -> anyhow::Result<()> {
        let mut config = WalletConfig::read(wallet_dir.as_ref())?;
        let params = config.network();
        let passphrase = config.prompt_passphrase()?;

        let key_info_vector = fs::read_to_string(&self.key_info)?;
        let key_info_vector = || key_info_vector.lines().filter(|line| !line.is_empty());

        let key_info = key_info_vector()
            .map(|line| {
                zip48::AccountPubKey::parse_key_info_expression(line, &params)
                    .ok_or_else(|| anyhow!("Invalid key info expression: {line}"))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let fvk = zip48::FullViewingKey::standard(self.required, key_info)
            .map_err(|e| anyhow!("{e:?}"))?;

        println!(
            "Wallet descriptor template: {}",
            fvk.wallet_descriptor_template()
        );
        println!("Key information vector:");
        for line in key_info_vector() {
            println!("{line}");
        }
        println!();

        // Decrypt the mnemonic to access the seed.
        let seed = config
            .decrypt_seed_with(passphrase.as_ref(), self.identity.as_deref())
            .context("Failed to decrypt wallet seed phrase")?
            .ok_or(anyhow!(
                "Seed must be present to enable generating a new account"
            ))?;

        let privkey = fvk
            .derive_matching_account_priv_key(seed.expose_secret())
            .map_err(|e| anyhow!("Failed to derive privkey from seed: {e}"))?;

        match privkey {
            None => println!("WARNING: This wallet is not a participant in the ZIP 48 account!"),
            Some(_) => {
                println!("This wallet is a participant in the ZIP 48 account.");
            }
        }

        Ok(())
    }
}
