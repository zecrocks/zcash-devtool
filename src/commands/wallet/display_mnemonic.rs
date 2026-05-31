use clap::Args;

use crate::config::WalletConfig;
use secrecy::ExposeSecret;

// Options accepted for the `display-mnemonic` command
#[derive(Debug, Args)]
pub(crate) struct Command {
    /// age identity file to decrypt the mnemonic phrase with (unencrypted wallets only)
    #[arg(short, long)]
    identity: Option<String>,

    /// allow the printing of the mnemonic to stdout; false by default
    #[arg(long, default_value = "false")]
    enable: bool,
}

impl Command {
    pub(crate) fn run(self, wallet_dir: Option<String>) -> anyhow::Result<()> {
        let mut config = WalletConfig::read(wallet_dir.as_ref())?;
        let passphrase = config.prompt_passphrase()?;

        if self.enable {
            if let Some(mnemonic_bytes) =
                config.decrypt_mnemonic_with(passphrase.as_ref(), self.identity.as_deref())?
            {
                println!("{}", std::str::from_utf8(mnemonic_bytes.expose_secret())?);
            } else {
                println!("No mnemonic recovery phrase is available for this wallet.");
            }
        } else {
            println!(
                "WARNING: This command is disabled by default because it prints your unencrypted \
                 mnemonic recovery phrase to `stdout`, which may result it being logged in your \
                 terminal history. Call this command with the `--enable` flag set to accept this \
                 risk and display the mnemonic."
            )
        }
        Ok(())
    }
}
