use clap::Args;
use zcash_client_backend::data_api::{Account, WalletRead};

use crate::{config::WalletConfig, data::open_wallet_db};

// Options accepted for the `list-accounts` command
#[derive(Debug, Args)]
pub(crate) struct Command {}

impl Command {
    pub(crate) fn run(self, wallet_dir: Option<String>) -> anyhow::Result<()> {
        let config = WalletConfig::read(wallet_dir.as_ref())?;
        let params = config.network();
        let passphrase = config.prompt_passphrase()?;
        let db_data = open_wallet_db(wallet_dir.as_ref(), params, (), (), passphrase.as_ref())?;

        for account_id in db_data.get_account_ids()?.iter() {
            let account = db_data.get_account(*account_id)?.unwrap();

            println!("Account {}", account_id.expose_uuid());
            if let Some(name) = account.name() {
                println!("     Name: {name}");
            }
            println!("     UIVK: {}", account.uivk().encode(&params));
            println!(
                "     UFVK: {}",
                account
                    .ufvk()
                    .map_or("None".to_owned(), |k| k.encode(&params))
            );
            println!("     Source: {:?}", account.source());
        }
        Ok(())
    }
}
