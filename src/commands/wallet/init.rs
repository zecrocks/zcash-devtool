use age::secrecy::ExposeSecret;
use bip0039::{Count, English, Mnemonic};
use clap::Args;
use secrecy::{ExposeSecret as _, SecretString, SecretVec, Zeroize};
use tokio::io::AsyncWriteExt;
use tonic::transport::Channel;

use zcash_client_backend::{
    data_api::{AccountBirthday, WalletWrite},
    proto::service::{self, compact_tx_streamer_client::CompactTxStreamerClient},
};
use zcash_protocol::consensus::{self, BlockHeight, Parameters};

use crate::{
    config::{prompt_new_passphrase, scrypt_recipient, WalletConfig},
    data::{init_dbs, Network},
    error,
    remote::ConnectionArgs,
};

// Options accepted for the `init` command
#[derive(Debug, Args)]
pub(crate) struct Command {
    /// A name for the account
    #[arg(long)]
    name: String,

    /// age identity file to encrypt the mnemonic phrase to (generated if it doesn't exist).
    ///
    /// Required unless `--encrypt-data` is set, in which case the wallet is protected by a
    /// password instead and no identity file is used.
    #[arg(short, long)]
    identity: Option<String>,

    /// Encrypt `data.sqlite` (via SQLCipher) and the seed with a wallet password.
    ///
    /// You will be prompted to set the password, and prompted again for it on each command
    /// that opens the wallet. The public block cache is left unencrypted.
    #[arg(long)]
    encrypt_data: bool,

    /// The wallet's birthday (default is current chain height)
    #[arg(long)]
    birthday: Option<u32>,

    /// The network the wallet will be used with: \"test\" or \"main\" (default is \"test\")
    #[arg(short, long)]
    #[arg(value_parser = Network::parse)]
    network: Network,

    #[command(flatten)]
    connection: ConnectionArgs,
}

impl Command {
    pub(crate) async fn run(self, wallet_dir: Option<String>) -> Result<(), anyhow::Error> {
        let opts = self;
        let params = consensus::Network::from(opts.network);

        let mut client = opts.connection.connect(params, wallet_dir.as_ref()).await?;

        // Get the current chain height (for the wallet's birthday and/or recover-until height).
        let chain_tip: u32 = client
            .get_latest_block(service::ChainSpec::default())
            .await?
            .into_inner()
            .height
            .try_into()
            .expect("block heights must fit into u32");

        // Determine how the seed will be encrypted: either to a wallet password (via an age
        // scrypt passphrase recipient) or to an age identity file.
        let passphrase = if opts.encrypt_data {
            Some(prompt_new_passphrase()?)
        } else {
            None
        };

        let recipients: Vec<Box<dyn age::Recipient + Send>> = if let Some(passphrase) = &passphrase {
            vec![Box::new(scrypt_recipient(passphrase))]
        } else {
            let identity = opts.identity.clone().ok_or_else(|| {
                anyhow::anyhow!("An age identity file (-i) is required unless --encrypt-data is set")
            })?;
            if tokio::fs::try_exists(&identity).await? {
                age::IdentityFile::from_file(identity)?
                    .to_recipients()?
                    .into_iter()
                    .map(|r| r as _)
                    .collect()
            } else {
                eprintln!("Generating a new age identity to encrypt the mnemonic phrase");
                let id = age::x25519::Identity::generate();
                let recipient = id.to_public();

                // Write it to the provided path so we have it for next time.
                let mut f = tokio::fs::File::create_new(identity).await?;
                f.write_all(
                    format!(
                        "# created: {}\n",
                        chrono::Local::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
                    )
                    .as_bytes(),
                )
                .await?;
                f.write_all(format!("# public key: {recipient}\n").as_bytes())
                    .await?;
                f.write_all(format!("{}\n", id.to_string().expose_secret()).as_bytes())
                    .await?;
                f.flush().await?;

                vec![Box::new(recipient) as _]
            }
        };

        // Parse or create the wallet's mnemonic phrase.
        let phrase = SecretString::new(rpassword::prompt_password(
            "Enter mnemonic (or just press Enter to generate a new one):",
        )?);
        let (mnemonic, recover_until) = if !phrase.expose_secret().is_empty() {
            (
                <Mnemonic<English>>::from_phrase(phrase.expose_secret())?,
                Some(chain_tip.into()),
            )
        } else {
            (Mnemonic::generate(Count::Words24), None)
        };

        let birthday = Self::get_wallet_birthday(
            client,
            opts.birthday
                .unwrap_or(chain_tip.saturating_sub(100))
                .into(),
            recover_until,
        )
        .await?;

        // Save the wallet keys to disk.
        WalletConfig::init_with_mnemonic(
            wallet_dir.as_ref(),
            recipients.iter().map(|r| r.as_ref() as _),
            &mnemonic,
            birthday.height(),
            opts.network.into(),
            opts.encrypt_data,
        )?;

        let seed = {
            let mut seed = mnemonic.to_seed("");
            let secret = seed.to_vec();
            seed.zeroize();
            SecretVec::new(secret)
        };

        Self::init_dbs(
            params,
            wallet_dir.as_ref(),
            &opts.name,
            &seed,
            birthday,
            None,
            passphrase.as_ref(),
        )
    }

    pub(crate) async fn get_wallet_birthday(
        mut client: CompactTxStreamerClient<Channel>,
        birthday_height: BlockHeight,
        recover_until: Option<BlockHeight>,
    ) -> Result<AccountBirthday, anyhow::Error> {
        // Fetch the tree state corresponding to the last block prior to the wallet's
        // birthday height. NOTE: THIS APPROACH LEAKS THE BIRTHDAY TO THE SERVER!
        let request = service::BlockId {
            height: u64::from(birthday_height).saturating_sub(1),
            ..Default::default()
        };
        let treestate = client.get_tree_state(request).await?.into_inner();
        let birthday = AccountBirthday::from_treestate(treestate, recover_until)
            .map_err(error::Error::from)?;

        Ok(birthday)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn init_dbs(
        params: impl Parameters + 'static,
        wallet_dir: Option<&String>,
        account_name: &str,
        seed: &SecretVec<u8>,
        birthday: AccountBirthday,
        key_source: Option<&str>,
        passphrase: Option<&SecretString>,
    ) -> Result<(), anyhow::Error> {
        // Initialise the block and wallet DBs.
        let mut db_data = init_dbs(params, wallet_dir, passphrase)?;

        // Add account.
        db_data.create_account(account_name, seed, &birthday, key_source)?;

        Ok(())
    }
}
