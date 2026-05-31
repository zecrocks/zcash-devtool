use anyhow::anyhow;
use rand::rngs::OsRng;
use secrecy::{ExposeSecret, SecretString};
use std::path::{Path, PathBuf};
use zcash_client_sqlite::chain::init::init_blockmeta_db;
use zcash_client_sqlite::util::SystemClock;
use zcash_client_sqlite::wallet::init::init_wallet_db;
use zcash_client_sqlite::{FsBlockDb, WalletDb};

use tracing::error;

use zcash_client_sqlite::chain::BlockMeta;
use zcash_protocol::consensus::{self, Parameters};

use crate::error;

pub(crate) const DEFAULT_WALLET_DIR: &str = "./zec_sqlite_wallet";
const BLOCKS_FOLDER: &str = "blocks";
const DATA_DB: &str = "data.sqlite";
const TOR_DIR: &str = "tor";

#[derive(Clone, Copy, Debug, Default)]
pub(crate) enum Network {
    #[default]
    Test,
    Main,
}

impl Network {
    pub(crate) fn parse(name: &str) -> Result<Network, String> {
        match name {
            "main" => Ok(Network::Main),
            "test" => Ok(Network::Test),
            other => Err(format!("Unsupported network: {other}")),
        }
    }

    pub(crate) fn name(&self) -> &str {
        match self {
            Network::Test => "test",
            Network::Main => "main",
        }
    }
}

impl From<Network> for consensus::Network {
    fn from(value: Network) -> Self {
        match value {
            Network::Test => consensus::Network::TestNetwork,
            Network::Main => consensus::Network::MainNetwork,
        }
    }
}

impl From<consensus::Network> for Network {
    fn from(value: consensus::Network) -> Self {
        match value {
            consensus::Network::TestNetwork => Network::Test,
            consensus::Network::MainNetwork => Network::Main,
        }
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

/// Opens a connection to a SQLite database, applying the SQLCipher key derived from the
/// given password when one is provided.
///
/// When `passphrase` is `None` the database is opened as ordinary (plaintext) SQLite. This
/// is used both for legacy unencrypted wallets and, deliberately, for the public block cache
/// (`blockmeta.sqlite`), which we never key. SQLCipher reads plaintext databases when no key
/// is set, so a SQLCipher-enabled build does not change the cache's on-disk format.
///
/// When `passphrase` is `Some`, SQLCipher runs PBKDF2-HMAC-SHA512 over the password against a
/// random salt stored in the database header, deriving the AES-256 key. We immediately issue a
/// trivial query so that an incorrect password fails fast with a friendly error rather than
/// surfacing deep inside a later wallet operation.
pub(crate) fn open_keyed_connection(
    path: impl AsRef<Path>,
    passphrase: Option<&SecretString>,
) -> Result<rusqlite::Connection, anyhow::Error> {
    let conn = rusqlite::Connection::open(path)?;
    if let Some(passphrase) = passphrase {
        // `PRAGMA key` returns a result row, so use `pragma_update` to drive the assignment.
        conn.pragma_update(None, "key", passphrase.expose_secret())?;
        // Force SQLCipher to read the header and verify the key.
        conn.query_row("SELECT count(*) FROM sqlite_master", [], |_| Ok(()))
            .map_err(|_| {
                anyhow!("Incorrect wallet password, or the database is corrupted.")
            })?;
    }
    Ok(conn)
}

/// Opens the wallet database ([`DATA_DB`]), applying the SQLCipher key when `passphrase` is
/// provided, and wraps it in a [`WalletDb`].
///
/// This mirrors [`WalletDb::for_path`] (which we cannot use directly because it always opens an
/// unkeyed connection): it loads the array virtual-table module and then hands the connection to
/// the public [`WalletDb::from_connection`] constructor, yielding exactly the same type every
/// call site already uses.
pub(crate) fn open_wallet_db<P: Parameters + 'static, CL, R>(
    wallet_dir: Option<&String>,
    params: P,
    clock: CL,
    rng: R,
    passphrase: Option<&SecretString>,
) -> Result<WalletDb<rusqlite::Connection, P, CL, R>, anyhow::Error> {
    let (_, db_data) = get_db_paths(wallet_dir);
    let conn = open_keyed_connection(db_data, passphrase)?;
    // Match `WalletDb::for_path`, which loads this module so that array-valued query
    // parameters work (e.g. in `list_tx`).
    rusqlite::vtab::array::load_module(&conn)?;
    Ok(WalletDb::from_connection(conn, params, clock, rng))
}

pub(crate) fn init_dbs<P: Parameters + 'static>(
    params: P,
    wallet_dir: Option<&String>,
    passphrase: Option<&SecretString>,
) -> Result<WalletDb<rusqlite::Connection, P, SystemClock, OsRng>, anyhow::Error> {
    // Initialise the block and wallet DBs.
    let (db_cache, _) = get_db_paths(wallet_dir);
    // The block cache is public chain data and is intentionally left unencrypted.
    let mut db_cache = FsBlockDb::for_path(db_cache).map_err(error::Error::from)?;
    // The wallet DB is keyed with the wallet password when encryption is enabled, so that
    // its schema and contents are written to disk already encrypted.
    let mut db_data = open_wallet_db(wallet_dir, params, SystemClock, OsRng, passphrase)?;
    init_blockmeta_db(&mut db_cache)?;
    init_wallet_db(&mut db_data, None)?;

    Ok(db_data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read as _;

    /// Reads the first 16 bytes of a file (the SQLite header magic for plaintext DBs).
    fn file_header(path: &Path) -> Vec<u8> {
        let mut f = std::fs::File::open(path).expect("file exists");
        let mut buf = vec![0u8; 16];
        let n = f.read(&mut buf).expect("read header");
        buf.truncate(n);
        buf
    }

    const SQLITE_MAGIC: &[u8] = b"SQLite format 3\0";

    /// An encrypted database does not have the plaintext SQLite header on disk, cannot be
    /// opened without the key, and round-trips data when the correct key is supplied.
    #[test]
    fn sqlcipher_encrypts_at_rest_and_round_trips() {
        let dir = std::env::temp_dir().join(format!("zdt-enc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("encrypted.sqlite");
        let password = SecretString::new("correct horse battery staple".to_owned());

        // Create an encrypted database and write a row.
        {
            let conn = open_keyed_connection(&path, Some(&password)).unwrap();
            conn.execute_batch("CREATE TABLE t(x TEXT); INSERT INTO t VALUES ('secret');")
                .unwrap();
        }

        // On-disk header must NOT be the plaintext SQLite magic.
        assert_ne!(
            file_header(&path),
            SQLITE_MAGIC,
            "encrypted DB must not have a plaintext SQLite header"
        );

        // Opening without a key fails to read the schema.
        {
            let conn = open_keyed_connection(&path, None).unwrap();
            assert!(
                conn.query_row("SELECT count(*) FROM t", [], |r| r.get::<_, i64>(0))
                    .is_err(),
                "an unkeyed open must not be able to read an encrypted DB"
            );
        }

        // Opening with the wrong key fails fast (our helper verifies the key on open).
        {
            let wrong = SecretString::new("nope".to_owned());
            assert!(
                open_keyed_connection(&path, Some(&wrong)).is_err(),
                "an incorrect key must be rejected"
            );
        }

        // Opening with the correct key reads the data back.
        {
            let conn = open_keyed_connection(&path, Some(&password)).unwrap();
            let value: String = conn
                .query_row("SELECT x FROM t", [], |r| r.get(0))
                .unwrap();
            assert_eq!(value, "secret");
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A database created with no passphrase is ordinary plaintext SQLite, even on a
    /// SQLCipher-enabled build. This is what keeps the public block cache readable.
    #[test]
    fn no_passphrase_is_plaintext() {
        let dir = std::env::temp_dir().join(format!("zdt-plain-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("plain.sqlite");

        {
            let conn = open_keyed_connection(&path, None).unwrap();
            conn.execute_batch("CREATE TABLE t(x INTEGER);").unwrap();
        }

        assert_eq!(
            file_header(&path),
            SQLITE_MAGIC,
            "an unkeyed DB must be plaintext SQLite"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
