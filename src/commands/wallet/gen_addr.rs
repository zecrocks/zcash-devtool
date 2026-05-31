use clap::Args;
use rand::rngs::OsRng;
use uuid::Uuid;
use zcash_client_backend::data_api::{Account, WalletWrite};
use zcash_client_sqlite::util::SystemClock;
use zcash_keys::{address::Address, keys::UnifiedAddressRequest};

use crate::{
    commands::{inspect::address::inspect, select_account},
    config::WalletConfig,
    data::open_wallet_db,
};

#[cfg(feature = "qr")]
use qrcode::{render::unicode, QrCode};

// Options accepted for the `generate-address` command
#[derive(Debug, Args)]
pub(crate) struct Command {
    /// The UUID of the account to list addresses for
    account_id: Option<Uuid>,

    /// A flag indicating whether a QR code should be displayed for the address.
    #[cfg(feature = "qr")]
    #[arg(long, default_value = "true")]
    display_qr: bool,
}

impl Command {
    pub(crate) fn run(self, wallet_dir: Option<String>) -> anyhow::Result<()> {
        let config = WalletConfig::read(wallet_dir.as_ref())?;
        let params = config.network();
        let passphrase = config.prompt_passphrase()?;
        let mut db_data =
            open_wallet_db(wallet_dir.as_ref(), params, SystemClock, OsRng, passphrase.as_ref())?;

        let account = select_account(&db_data, self.account_id)?;

        println!("Account {:?}", account.id());
        let (ua, _) = db_data
            .get_next_available_address(account.id(), UnifiedAddressRequest::AllAvailableKeys)?
            .unwrap();
        let ua_str = ua.encode(&params);
        println!("     Address: {ua_str}");

        let zaddr = Address::from(ua).to_zcash_address(&params);
        inspect(zaddr);

        #[cfg(feature = "qr")]
        if self.display_qr {
            let code = QrCode::new(ua_str)?;
            let ua_qr = code
                .render::<unicode::Dense1x2>()
                .dark_color(unicode::Dense1x2::Light)
                .light_color(unicode::Dense1x2::Dark)
                .quiet_zone(true)
                .build();
            println!("{}", ua_qr);
        }

        Ok(())
    }
}
