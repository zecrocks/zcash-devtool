use clap::Args;
use nonempty::NonEmpty;
use rand::rngs::OsRng;
use zcash_client_backend::data_api::scanning::ScanPriority;
use zcash_client_sqlite::util::SystemClock;

use crate::{config::WalletConfig, data::open_wallet_db};

#[derive(Debug, Args)]
pub(crate) struct Command {}

impl Command {
    pub(crate) async fn run(self, wallet_dir: Option<String>) -> Result<(), anyhow::Error> {
        let config = WalletConfig::read(wallet_dir.as_ref())?;
        let params = config.network();
        let passphrase = config.prompt_passphrase()?;
        let mut db_data =
            open_wallet_db(wallet_dir.as_ref(), params, SystemClock, OsRng, passphrase.as_ref())?;

        if let Some(corrupt_ranges) = NonEmpty::from_vec(db_data.check_witnesses()?) {
            let corrupt_ranges_len = corrupt_ranges.len();
            for range in corrupt_ranges.iter() {
                eprintln!("Found corrupt witness, requires rescan of range {range:?}");
            }

            db_data.queue_rescans(corrupt_ranges, ScanPriority::FoundNote)?;

            eprintln!("Updated {corrupt_ranges_len} scan ranges");
        } else {
            eprintln!("No corrupt witnesses found in the tree");
        }

        Ok(())
    }
}
