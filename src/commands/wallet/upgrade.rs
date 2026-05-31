use clap::Args;
use rand::rngs::OsRng;
use zcash_client_sqlite::{
    chain::init::init_blockmeta_db,
    util::SystemClock,
    wallet::init::{init_wallet_db, WalletMigrationError},
    FsBlockDb,
};

use crate::{
    config::WalletConfig,
    data::{get_db_paths, open_wallet_db},
    error,
};

// Options accepted for the `upgrade` command
#[derive(Debug, Args)]
pub(crate) struct Command {
    /// age identity file to decrypt the mnemonic phrase with (unencrypted wallets only)
    #[arg(short, long)]
    identity: Option<String>,
}

impl Command {
    pub(crate) fn run(self, wallet_dir: Option<String>) -> Result<(), anyhow::Error> {
        let mut config = WalletConfig::read(wallet_dir.as_ref())?;
        let params = config.network();
        let passphrase = config.prompt_passphrase()?;

        let (fsblockdb_root, _) = get_db_paths(wallet_dir.as_ref());
        let mut db_cache = FsBlockDb::for_path(fsblockdb_root).map_err(error::Error::from)?;
        let mut db_data =
            open_wallet_db(wallet_dir.as_ref(), params, SystemClock, OsRng, passphrase.as_ref())?;

        init_blockmeta_db(&mut db_cache)?;

        if let Err(e) = init_wallet_db(&mut db_data, None) {
            if matches!(&e, schemerz::MigratorError::Migration {
                error, ..
            } if matches!(error, WalletMigrationError::SeedRequired))
            {
                let seed = config.decrypt_seed_with(passphrase.as_ref(), self.identity.as_deref())?;
                init_wallet_db(&mut db_data, seed)?;
            } else {
                return Err(e.into());
            }
        }

        println!("Wallet successfully upgraded!");
        Ok(())
    }
}
