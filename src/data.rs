use rand::rngs::OsRng;
use std::path::{Path, PathBuf};
use zcash_client_sqlite::chain::init::init_blockmeta_db;
use zcash_client_sqlite::util::SystemClock;
use zcash_client_sqlite::wallet::init::init_wallet_db;
use zcash_client_sqlite::{FsBlockDb, WalletDb};

use tracing::error;

use zcash_client_sqlite::chain::BlockMeta;
use zcash_protocol::consensus::{
    BlockHeight, NetworkType, NetworkUpgrade, Parameters, MAIN_NETWORK, TEST_NETWORK,
};
use zcash_protocol::local_consensus::LocalNetwork;

use crate::error;

pub(crate) const DEFAULT_WALLET_DIR: &str = "./zec_sqlite_wallet";
const BLOCKS_FOLDER: &str = "blocks";
const DATA_DB: &str = "data.sqlite";
const TOR_DIR: &str = "tor";

/// The network a devtool wallet operates on. Implements [`Parameters`] directly so it threads
/// through the whole librustzcash wallet stack (DB, key derivation, address encoding, transaction
/// building) as the single `P` value — including `Regtest`, which librustzcash's own
/// [`consensus::Network`](zcash_protocol::consensus::Network) (main/test only) cannot represent.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) enum Network {
    #[default]
    Test,
    Main,
    /// A local regtest chain; activation heights are carried by the inner [`LocalNetwork`].
    Regtest(LocalNetwork),
}

impl Network {
    pub(crate) fn parse(name: &str) -> Result<Network, String> {
        match name {
            "main" => Ok(Network::Main),
            "test" => Ok(Network::Test),
            "regtest" => Ok(Network::Regtest(regtest_local())),
            other => Err(format!("Unsupported network: {other}")),
        }
    }

    pub(crate) fn name(&self) -> &str {
        match self {
            Network::Test => "test",
            Network::Main => "main",
            Network::Regtest(_) => "regtest",
        }
    }
}

impl Parameters for Network {
    fn network_type(&self) -> NetworkType {
        match self {
            Network::Main => MAIN_NETWORK.network_type(),
            Network::Test => TEST_NETWORK.network_type(),
            Network::Regtest(local) => local.network_type(),
        }
    }

    fn activation_height(&self, nu: NetworkUpgrade) -> Option<BlockHeight> {
        match self {
            Network::Main => MAIN_NETWORK.activation_height(nu),
            Network::Test => TEST_NETWORK.activation_height(nu),
            Network::Regtest(local) => local.activation_height(nu),
        }
    }
}

impl From<NetworkType> for Network {
    fn from(value: NetworkType) -> Self {
        match value {
            NetworkType::Main => Network::Main,
            NetworkType::Test => Network::Test,
            NetworkType::Regtest => Network::Regtest(regtest_local()),
        }
    }
}

/// A regtest network with every upgrade active from height 1 (NU5/Orchard included) — the
/// zebra/zcashd regtest convention, matching `zecd`'s regtest configuration.
#[allow(unexpected_cfgs)]
fn regtest_local() -> LocalNetwork {
    let h = Some(BlockHeight::from_u32(1));
    LocalNetwork {
        overwinter: h,
        sapling: h,
        blossom: h,
        heartwood: h,
        canopy: h,
        nu5: h,
        nu6: h,
        // NU6 ceiling for now: activating NU6.1 makes zebra's z_gettreestate fail ("block not in
        // the main chain") with lightwalletd v0.4.19. Must match zecd + the regtest harness.
        // Real NU6.1/NU6.2 support needs a librustzcash bump.
        nu6_1: None,
        #[cfg(zcash_unstable = "nu7")]
        nu7: h,
        #[cfg(zcash_unstable = "zfuture")]
        z_future: h,
    }
}

pub(crate) fn get_db_paths<P: AsRef<Path>>(wallet_dir: Option<P>) -> (PathBuf, PathBuf) {
    let a = wallet_dir
        .as_ref()
        .map(|p| p.as_ref())
        .unwrap_or(DEFAULT_WALLET_DIR.as_ref())
        .to_owned();
    let mut b = a.clone();
    b.push(DATA_DB);
    (a, b)
}

pub(crate) fn get_block_path(fsblockdb_root: &Path, meta: &BlockMeta) -> PathBuf {
    meta.block_file_path(&fsblockdb_root.join(BLOCKS_FOLDER))
}

pub(crate) fn get_tor_dir<P: AsRef<Path>>(wallet_dir: Option<P>) -> PathBuf {
    wallet_dir
        .as_ref()
        .map(|p| p.as_ref())
        .unwrap_or(DEFAULT_WALLET_DIR.as_ref())
        .join(TOR_DIR)
}

pub(crate) async fn erase_wallet_state<P: AsRef<Path>>(wallet_dir: Option<P>) {
    let (fsblockdb_root, db_data) = get_db_paths(wallet_dir);
    let blocks_meta = fsblockdb_root.join("blockmeta.sqlite");
    let blocks_folder = fsblockdb_root.join(BLOCKS_FOLDER);

    if let Err(e) = tokio::fs::remove_dir_all(&blocks_folder).await {
        error!("Failed to remove {:?}: {}", blocks_folder, e);
    }

    if let Err(e) = tokio::fs::remove_file(&blocks_meta).await {
        error!("Failed to remove {:?}: {}", blocks_meta, e);
    }

    if let Err(e) = tokio::fs::remove_file(&db_data).await {
        error!("Failed to remove {:?}: {}", db_data, e);
    }
}

pub(crate) fn init_dbs<P: Parameters + 'static>(
    params: P,
    wallet_dir: Option<&String>,
) -> Result<WalletDb<rusqlite::Connection, P, SystemClock, OsRng>, anyhow::Error> {
    // Initialise the block and wallet DBs.
    let (db_cache, db_data) = get_db_paths(wallet_dir);
    let mut db_cache = FsBlockDb::for_path(db_cache).map_err(error::Error::from)?;
    let mut db_data = WalletDb::for_path(db_data, params, SystemClock, OsRng)?;
    init_blockmeta_db(&mut db_cache)?;
    init_wallet_db(&mut db_data, None)?;

    Ok(db_data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regtest_parses_and_activates_orchard_from_genesis() {
        let net = Network::parse("regtest").expect("regtest is a known network");
        assert_eq!(net.name(), "regtest");
        assert_eq!(net.network_type(), NetworkType::Regtest);
        // Every upgrade, including NU5 (Orchard), is active from height 1, matching zecd's
        // regtest configuration and the zebra/zcashd regtest convention.
        assert_eq!(
            net.activation_height(NetworkUpgrade::Nu5),
            Some(BlockHeight::from_u32(1))
        );
        assert_eq!(
            net.activation_height(NetworkUpgrade::Canopy),
            Some(BlockHeight::from_u32(1))
        );
    }

    #[test]
    fn main_and_test_networks_still_parse() {
        assert_eq!(
            Network::parse("main").unwrap().network_type(),
            NetworkType::Main
        );
        assert_eq!(
            Network::parse("test").unwrap().network_type(),
            NetworkType::Test
        );
        assert!(Network::parse("bogus").is_err());
    }
}
