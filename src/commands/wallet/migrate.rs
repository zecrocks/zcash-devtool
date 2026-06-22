use anyhow::anyhow;
use clap::Args;
use rand::rngs::OsRng;
use secrecy::ExposeSecret;
use uuid::Uuid;

use zcash_client_backend::{
    data_api::{
        Account, WalletRead,
        wallet::{ConfirmationsPolicy, SpendingKeys, create_orchard_to_ironwood_transaction},
    },
    fees::StandardFeeRule,
    proto::service,
    wallet::OvkPolicy,
};
use zcash_client_sqlite::{WalletDb, util::SystemClock};
use zcash_keys::keys::UnifiedSpendingKey;
use zcash_proofs::prover::LocalTxProver;
use zcash_protocol::value::Zatoshis;

use crate::{
    commands::select_account, config::WalletConfig, data::get_db_paths, error,
    remote::ConnectionArgs,
};

// Options accepted for the `migrate-to-ironwood` command
#[derive(Debug, Args)]
pub(crate) struct Command {
    /// The UUID of the account to migrate Orchard funds from
    account_id: Option<Uuid>,

    /// The minimum amount (in zatoshis) of Orchard value to migrate to Ironwood.
    ///
    /// Note selection picks at least this much value; the resulting transaction
    /// then migrates the full selected Orchard value minus fees, so no Orchard
    /// change output is created.
    #[arg(long)]
    amount: u64,

    /// age identity file to decrypt the mnemonic phrase with
    #[arg(short, long)]
    identity: String,

    #[command(flatten)]
    connection: ConnectionArgs,
}

impl Command {
    pub(crate) async fn run(self, wallet_dir: Option<String>) -> Result<(), anyhow::Error> {
        let mut config = WalletConfig::read(wallet_dir.as_ref())?;
        let params = config.network();

        let (_, db_data) = get_db_paths(wallet_dir.as_ref());
        let mut db_data = WalletDb::for_path(db_data, params, SystemClock, OsRng)?;
        let account = select_account(&db_data, self.account_id)?;
        let derivation = account.source().key_derivation().ok_or(anyhow!(
            "Cannot spend from view-only accounts; an Ironwood migration requires spending keys"
        ))?;

        // Decrypt the mnemonic to access the seed.
        let identities = age::IdentityFile::from_file(self.identity)?.into_identities()?;
        let seed = config
            .decrypt_seed(identities.iter().map(|i| i.as_ref() as _))?
            .ok_or(anyhow!("Seed must be present to enable sending"))?;

        let usk = UnifiedSpendingKey::from_seed(
            &params,
            seed.expose_secret(),
            derivation.account_index(),
        )
        .map_err(error::Error::from)?;

        let mut client = self.connection.connect(params, wallet_dir.as_ref()).await?;

        // Build, prove, sign, and persist the Orchard -> Ironwood migration
        // transaction. This spends only Orchard notes and creates a single
        // Ironwood (V6) output to the account's internal Orchard receiver.
        println!("Creating Ironwood migration transaction...");
        let prover = LocalTxProver::bundled();
        let amount = Zatoshis::from_u64(self.amount)?;

        let migration = create_orchard_to_ironwood_transaction(
            &mut db_data,
            &params,
            &prover,
            &prover,
            &SpendingKeys::from_unified_spending_key(usk),
            OvkPolicy::Sender,
            amount,
            None,
            &StandardFeeRule::Zip317,
            ConfirmationsPolicy::MIN,
        )
        .map_err(error::Error::Migrate)?;

        // Send the transaction.
        println!(
            "Migrating {} zatoshis to Ironwood (fee {} zatoshis)...",
            u64::from(migration.migrated_amount()),
            u64::from(migration.fee_amount()),
        );
        let (txid, raw_tx) = db_data
            .get_transaction(migration.txid())?
            .map(|tx| {
                let mut raw_tx = service::RawTransaction::default();
                tx.write(&mut raw_tx.data).unwrap();
                (tx.txid(), raw_tx)
            })
            .ok_or(anyhow!(
                "Transaction not found for id {:?}",
                migration.txid()
            ))?;
        let response = client.send_transaction(raw_tx).await?.into_inner();

        if response.error_code != 0 {
            Err(error::Error::SendFailed {
                code: response.error_code,
                reason: response.error_message,
            }
            .into())
        } else {
            println!("{txid}");
            Ok(())
        }
    }
}
