use anyhow::anyhow;
use clap::Args;
use uuid::Uuid;
use zcash_client_backend::data_api::{Account as _, InputSource, WalletRead};
use zcash_protocol::ShieldedProtocol;

use crate::{
    commands::select_account, config::WalletConfig, data::open_wallet_db, error, ui::format_zec,
};

// Options accepted for the `list-unspent` command
#[derive(Debug, Args)]
pub(crate) struct Command {
    /// The UUID of the account for which to list unspent funds
    account_id: Option<Uuid>,
}

impl Command {
    pub(crate) fn run(self, wallet_dir: Option<String>) -> Result<(), anyhow::Error> {
        let config = WalletConfig::read(wallet_dir.as_ref())?;
        let params = config.network();
        let passphrase = config.prompt_passphrase()?;

        let db_data = open_wallet_db(wallet_dir.as_ref(), params, (), (), passphrase.as_ref())?;
        let account = select_account(&db_data, self.account_id)?;

        let chain_height = db_data
            .chain_height()?
            .ok_or(error::WalletErrorT::ScanRequired)
            .map_err(|e| anyhow!("{:?}", e))?;
        let target_height = (chain_height + 1).into();

        let notes = db_data.select_unspent_notes(
            account.id(),
            &[ShieldedProtocol::Sapling, ShieldedProtocol::Orchard],
            target_height,
            &[],
        )?;

        for note in notes.sapling() {
            println!(
                "Sapling {}: {}",
                note.internal_note_id(),
                format_zec(note.note_value()?)
            );
        }

        for note in notes.orchard() {
            println!(
                "Orchard {}: {}",
                note.internal_note_id(),
                format_zec(note.note_value()?)
            );
        }

        Ok(())
    }
}
