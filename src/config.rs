use anyhow::anyhow;
use bip0039::{English, Mnemonic};
use std::fs::{self, File};
use std::io::{BufReader, Read, Write};
use std::path::Path;

use secrecy::{ExposeSecret, SecretString, SecretVec, Zeroize};
use serde::{Deserialize, Serialize};

use zcash_protocol::consensus::{self, BlockHeight, Parameters};

use crate::{
    data::{Network, DEFAULT_WALLET_DIR},
    error,
};

const KEYS_FILE: &str = "keys.toml";

/// Environment variable that, if set, supplies the wallet password non-interactively.
///
/// This is a convenience for scripting and testing; setting it exposes the password to
/// the process environment, so prefer the interactive prompt for sensitive wallets.
pub(crate) const PASSWORD_ENV_VAR: &str = "ZCASH_WALLET_PASSWORD";

pub(crate) struct WalletConfig {
    network: consensus::Network,
    seed_ciphertext: Option<String>,
    birthday: BlockHeight,
    encrypted: bool,
}

/// Converts a crate-level (`secrecy` 0.8) [`SecretString`] into the (`secrecy` 0.10)
/// `SecretString` type that the `age` crate's passphrase API expects.
///
/// `age` re-exports its own `secrecy` version, so we bridge the two here in one place.
fn to_age_secret(passphrase: &SecretString) -> age::secrecy::SecretString {
    age::secrecy::SecretString::from(passphrase.expose_secret().clone())
}

/// Builds an `age` passphrase recipient for encrypting the wallet seed to a password.
pub(crate) fn scrypt_recipient(passphrase: &SecretString) -> age::scrypt::Recipient {
    age::scrypt::Recipient::new(to_age_secret(passphrase))
}

/// Builds an `age` passphrase identity for decrypting the wallet seed with a password.
fn scrypt_identity(passphrase: &SecretString) -> age::scrypt::Identity {
    age::scrypt::Identity::new(to_age_secret(passphrase))
}

/// Prompts for the wallet password, preferring the [`PASSWORD_ENV_VAR`] environment
/// variable when set so that commands can be scripted.
fn read_password(prompt: &str) -> Result<SecretString, anyhow::Error> {
    if let Ok(password) = std::env::var(PASSWORD_ENV_VAR) {
        return Ok(SecretString::new(password));
    }
    Ok(SecretString::new(rpassword::prompt_password(prompt)?))
}

/// Prompts the user to set a new wallet password, requiring confirmation.
///
/// Honours [`PASSWORD_ENV_VAR`] for non-interactive use (in which case no confirmation
/// is required, since there is nothing to mistype).
pub(crate) fn prompt_new_passphrase() -> Result<SecretString, anyhow::Error> {
    if let Ok(password) = std::env::var(PASSWORD_ENV_VAR) {
        if password.is_empty() {
            return Err(anyhow!("{PASSWORD_ENV_VAR} must not be empty"));
        }
        return Ok(SecretString::new(password));
    }

    let password = SecretString::new(rpassword::prompt_password("Enter a new wallet password: ")?);
    if password.expose_secret().is_empty() {
        return Err(anyhow!("Wallet password must not be empty"));
    }
    let confirm =
        SecretString::new(rpassword::prompt_password("Confirm the new wallet password: ")?);
    if password.expose_secret() != confirm.expose_secret() {
        return Err(anyhow!("Passwords did not match"));
    }
    Ok(password)
}

impl WalletConfig {
    pub(crate) fn init_with_mnemonic<'a, P: AsRef<Path>>(
        wallet_dir: Option<P>,
        recipients: impl Iterator<Item = &'a dyn age::Recipient>,
        mnemonic: &Mnemonic,
        birthday: BlockHeight,
        network: consensus::Network,
        encrypted: bool,
    ) -> Result<(), anyhow::Error> {
        init_wallet_config(
            wallet_dir,
            Some(encrypt_mnemonic(recipients, mnemonic)?),
            birthday,
            network,
            encrypted,
        )
    }

    pub(crate) fn init_without_mnemonic<P: AsRef<Path>>(
        wallet_dir: Option<P>,
        birthday: BlockHeight,
        network: consensus::Network,
        encrypted: bool,
    ) -> Result<(), anyhow::Error> {
        init_wallet_config(wallet_dir, None, birthday, network, encrypted)
    }

    pub(crate) fn decrypt_seed<'a>(
        &mut self,
        identities: impl Iterator<Item = &'a dyn age::Identity>,
    ) -> Result<Option<SecretVec<u8>>, anyhow::Error> {
        self.seed_ciphertext
            .as_ref()
            .map(|ciphertext| decrypt_seed(identities, ciphertext))
            .transpose()
    }

    pub(crate) fn decrypt_mnemonic<'a>(
        &mut self,
        identities: impl Iterator<Item = &'a dyn age::Identity>,
    ) -> Result<Option<SecretVec<u8>>, anyhow::Error> {
        self.seed_ciphertext
            .as_ref()
            .map(|ciphertext| decrypt_mnemonic(identities, ciphertext))
            .transpose()
    }

    /// Prompts for the wallet password if (and only if) this wallet is encrypted.
    ///
    /// Returns `None` for unencrypted (legacy) wallets, in which case no prompt is shown
    /// and callers fall back to the age identity-file flow. The returned password is used
    /// both to open the SQLCipher-encrypted `data.sqlite` and to decrypt the seed, so a
    /// command only ever prompts once.
    pub(crate) fn prompt_passphrase(&self) -> Result<Option<SecretString>, anyhow::Error> {
        if self.encrypted {
            Ok(Some(read_password("Enter wallet password: ")?))
        } else {
            Ok(None)
        }
    }

    /// Decrypts the wallet seed using either the wallet password (for encrypted wallets)
    /// or an age identity file (for legacy wallets).
    ///
    /// Exactly one of `passphrase` / `identity_file` is expected to be meaningful: encrypted
    /// wallets pass the password obtained from [`Self::prompt_passphrase`]; legacy wallets
    /// pass the `-i` identity-file path.
    pub(crate) fn decrypt_seed_with(
        &mut self,
        passphrase: Option<&SecretString>,
        identity_file: Option<&str>,
    ) -> Result<Option<SecretVec<u8>>, anyhow::Error> {
        match passphrase {
            Some(password) => {
                let identity = scrypt_identity(password);
                self.decrypt_seed(std::iter::once(&identity as &dyn age::Identity))
            }
            None => {
                let identities = load_file_identities(identity_file)?;
                self.decrypt_seed(identities.iter().map(|i| i.as_ref() as _))
            }
        }
    }

    /// Decrypts the wallet mnemonic, mirroring [`Self::decrypt_seed_with`].
    pub(crate) fn decrypt_mnemonic_with(
        &mut self,
        passphrase: Option<&SecretString>,
        identity_file: Option<&str>,
    ) -> Result<Option<SecretVec<u8>>, anyhow::Error> {
        match passphrase {
            Some(password) => {
                let identity = scrypt_identity(password);
                self.decrypt_mnemonic(std::iter::once(&identity as &dyn age::Identity))
            }
            None => {
                let identities = load_file_identities(identity_file)?;
                self.decrypt_mnemonic(identities.iter().map(|i| i.as_ref() as _))
            }
        }
    }

    pub(crate) fn network(&self) -> consensus::Network {
        self.network
    }

    pub(crate) fn birthday(&self) -> BlockHeight {
        self.birthday
    }
}

fn init_wallet_config<P: AsRef<Path>>(
    wallet_dir: Option<P>,
    mnemonic: Option<String>,
    birthday: BlockHeight,
    network: consensus::Network,
    encrypted: bool,
) -> Result<(), anyhow::Error> {
    // Create the wallet directory.
    let wallet_dir = wallet_dir
        .as_ref()
        .map(|p| p.as_ref())
        .unwrap_or(DEFAULT_WALLET_DIR.as_ref());
    fs::create_dir_all(wallet_dir)?;

    // Write the mnemonic phrase to disk along with its birthday.
    let mut keys_file = {
        let mut p = wallet_dir.to_owned();
        p.push(KEYS_FILE);
        fs::OpenOptions::new().create_new(true).write(true).open(p)
    }?;

    let config = ConfigEncoding {
        mnemonic,
        network: Some(Network::from(network).name().to_string()),
        birthday: Some(u32::from(birthday)),
        encrypted: encrypted.then_some(true),
    };

    let config_str = toml::to_string(&config)
        .map_err::<anyhow::Error, _>(|_| anyhow!("error writing wallet config"))?;

    write!(&mut keys_file, "{config_str}")?;

    Ok(())
}

impl WalletConfig {
    pub(crate) fn read<P: AsRef<Path>>(wallet_dir: Option<P>) -> Result<Self, anyhow::Error> {
        let mut keys_file = {
            let mut p = wallet_dir
                .as_ref()
                .map(|p| p.as_ref())
                .unwrap_or(DEFAULT_WALLET_DIR.as_ref())
                .to_owned();
            p.push(KEYS_FILE);
            BufReader::new(File::open(p)?)
        };

        let mut conf_str = "".to_string();
        keys_file.read_to_string(&mut conf_str)?;
        let config: ConfigEncoding = toml::from_str(&conf_str)?;

        let network = config.network.map_or_else(
            || Ok(consensus::Network::TestNetwork),
            |network_name| {
                Network::parse(network_name.trim())
                    .map(consensus::Network::from)
                    .map_err(|_| error::Error::InvalidKeysFile)
            },
        )?;

        let birthday = config.birthday.map(BlockHeight::from).unwrap_or(
            network
                .activation_height(consensus::NetworkUpgrade::Sapling)
                .expect("Sapling activation height is known."),
        );

        Ok(Self {
            network,
            seed_ciphertext: config.mnemonic,
            birthday,
            encrypted: config.encrypted.unwrap_or(false),
        })
    }
}

#[derive(Deserialize, Serialize)]
struct ConfigEncoding {
    mnemonic: Option<String>,
    network: Option<String>,
    birthday: Option<u32>,
    /// Whether `data.sqlite` and the seed are password-protected. Absent in wallets
    /// created before encryption support, which are treated as unencrypted.
    #[serde(skip_serializing_if = "Option::is_none")]
    encrypted: Option<bool>,
}

/// Loads age identities from the given identity-file path, erroring helpfully if no path
/// was provided (which happens when a legacy wallet command is missing its `-i` flag).
fn load_file_identities(
    identity_file: Option<&str>,
) -> Result<Vec<Box<dyn age::Identity>>, anyhow::Error> {
    let path = identity_file.ok_or_else(|| {
        anyhow!("An age identity file (-i) is required to decrypt this wallet's seed")
    })?;
    Ok(age::IdentityFile::from_file(path.to_owned())?.into_identities()?)
}

fn encrypt_mnemonic<'a>(
    recipients: impl Iterator<Item = &'a dyn age::Recipient>,
    mnemonic: &Mnemonic,
) -> Result<String, anyhow::Error> {
    let encryptor = age::Encryptor::with_recipients(recipients)?;
    let mut ciphertext = vec![];
    let mut writer = encryptor.wrap_output(age::armor::ArmoredWriter::wrap_output(
        &mut ciphertext,
        age::armor::Format::AsciiArmor,
    )?)?;
    writer.write_all(mnemonic.phrase().as_bytes())?;
    writer.finish().and_then(|armor| armor.finish())?;
    Ok(String::from_utf8(ciphertext).expect("armor is valid UTF-8"))
}

fn decrypt_mnemonic<'a>(
    identities: impl Iterator<Item = &'a dyn age::Identity>,
    ciphertext: &str,
) -> Result<SecretVec<u8>, anyhow::Error> {
    let decryptor = age::Decryptor::new(age::armor::ArmoredReader::new(ciphertext.as_bytes()))?;
    let mut buf = vec![];
    // We intentionally do not use `?` on the result of the following expression because doing so
    // in the case of a partial failure could result in part of the secret data being read into
    // `buf`, which would not then be properly zeroized. Instead, we take ownership of the buffer
    // in construction of a `SecretVec` to ensure that the memory is zeroed out when we raise
    // the error on the following line.
    let ret = decryptor.decrypt(identities)?.read_to_end(&mut buf);
    let res = SecretVec::new(buf);
    ret?;
    Ok(res)
}

fn decrypt_seed<'a>(
    identities: impl Iterator<Item = &'a dyn age::Identity>,
    ciphertext: &str,
) -> Result<SecretVec<u8>, anyhow::Error> {
    let mnemonic_bytes = decrypt_mnemonic(identities, ciphertext)?;
    let mnemonic = std::str::from_utf8(mnemonic_bytes.expose_secret())?;

    let mut seed_bytes = <Mnemonic<English>>::from_phrase(mnemonic)?.to_seed("");
    let seed = SecretVec::new(seed_bytes.to_vec());
    seed_bytes.zeroize();

    Ok(seed)
}
