use anyhow::anyhow;
use clap::Args;
use rand::rngs::OsRng;
use zcash_client_backend::{
    data_api::{Account, WalletRead},
    proto::service,
};
use zcash_client_sqlite::util::SystemClock;

use crate::{
    config::WalletConfig,
    data::{erase_wallet_state, open_wallet_db},
    remote::ConnectionArgs,
};

// Options accepted for the `reset` command
#[derive(Debug, Args)]
pub(crate) struct Command {
    /// age identity file to decrypt the mnemonic phrase with (unencrypted wallets only)
    #[arg(short, long)]
    identity: Option<String>,

    #[command(flatten)]
    connection: ConnectionArgs,
}

impl Command {
    pub(crate) async fn run(self, wallet_dir: Option<String>) -> Result<(), anyhow::Error> {
        // Load the wallet network, seed, and birthday from disk.
        let mut config = WalletConfig::read(wallet_dir.as_ref())?;
        let params = config.network();
        let passphrase = config.prompt_passphrase()?;

        // Connect to the client (for re-initializing the wallet).
        let mut client = self.connection.connect(params, wallet_dir.as_ref()).await?;

        // Get the current chain height (for the wallet's recover-until height).
        let chain_tip = client
            .get_latest_block(service::ChainSpec::default())
            .await?
            .into_inner()
            .height
            .try_into()
            .expect("block heights must fit into u32");

        // Get the account name and key source to preserve them.
        let (account_name, key_source) = {
            let db_data = open_wallet_db(
                wallet_dir.as_ref(),
                params,
                SystemClock,
                OsRng,
                passphrase.as_ref(),
            )?;

            let account_id = *db_data
                .get_account_ids()?
                .first()
                .ok_or(anyhow!("Wallet has no accounts"))?;

            let account = db_data.get_account(account_id)?.expect("exists");
            (
                account.name().map(String::from),
                account.source().key_source().map(String::from),
            )
        };

        let birthday =
            super::init::Command::get_wallet_birthday(client, config.birthday(), Some(chain_tip))
                .await?;

        // Erase the wallet state (excluding key material).
        erase_wallet_state(wallet_dir.as_ref()).await;

        // Decrypt the mnemonic to access the seed.
        let seed = config
            .decrypt_seed_with(passphrase.as_ref(), self.identity.as_deref())?
            .ok_or(anyhow!("Seed is required for database reset"))?;

        // Re-initialize the wallet state.
        super::init::Command::init_dbs(
            params,
            wallet_dir.as_ref(),
            account_name.as_deref().unwrap_or(""),
            &seed,
            birthday,
            key_source.as_deref(),
            passphrase.as_ref(),
        )
    }
}
