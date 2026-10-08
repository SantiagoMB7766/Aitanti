//! Offline encrypted Aitanti vault (MVP format 1).
//!
//! The complete profile is encrypted using AES-256-GCM. A new 256-bit key is
//! derived from the entered passphrase and random per-file salt via Argon2id.
//! There is no plaintext key or passphrase in the serialized vault file.
//! This file format is intentionally frozen as a demo format, NOT production.

use std::{
    error::Error,
    fmt,
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::Path,
};

use argon2::{Algorithm, Argon2, Params, Version};
use aws_lc_rs::{
    aead::{self, Aad, LessSafeKey, Nonce, UnboundKey},
    rand,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"AITVLT01";
const FORMAT_VERSION: u16 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const KEY_LEN: usize = 32;
const HEADER_LEN: usize = 8 + 2 + SALT_LEN + NONCE_LEN;
const MAX_VAULT_BYTES: usize = 128 * 1024;

/// Fixed parameters for format 1. A future parameter change requires a format
/// migration and explicit re-encryption, never guessing parameters on unlock.
const ARGON2_MEMORY_KIB: u32 = 64 * 1024;
const ARGON2_ITERATIONS: u32 = 3;
const ARGON2_LANES: u32 = 1;

#[derive(Debug)]
pub enum VaultError {
    InvalidFormat,
    TooLarge,
    WeakPassphrase,
    Kdf,
    Random,
    Encryption,
    UnlockFailed,
    Io(std::io::Error),
    Encoding,
    UnsafeFile,
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFormat => write!(f, "invalid or unsupported Aitanti vault format"),
            Self::TooLarge => write!(f, "vault exceeds the size limit"),
            Self::WeakPassphrase => write!(f, "passphrase must have at least 12 bytes"),
            Self::Kdf => write!(f, "key derivation failed"),
            Self::Random => write!(f, "secure randomness failed"),
            Self::Encryption => write!(f, "vault encryption failed"),
            Self::UnlockFailed => write!(
                f,
                "vault authentication failed (wrong passphrase or altered file)"
            ),
            Self::Io(error) => write!(f, "vault filesystem operation failed: {error}"),
            Self::Encoding => write!(f, "vault payload could not be decoded"),
            Self::UnsafeFile => write!(f, "vault must be a regular, private file, not a symlink"),
        }
    }
}

impl Error for VaultError {}

impl From<std::io::Error> for VaultError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

/// Date with checked Gregorian calendar fields; no implicit system-clock access.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Date {
    pub year: u16,
    pub month: u8,
    pub day: u8,
}

impl Date {
    pub fn new(year: u16, month: u8, day: u8) -> Result<Self, VaultError> {
        let leap =
            year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
        let days = match month {
            1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
            4 | 6 | 9 | 11 => 30,
            2 if leap => 29,
            2 => 28,
            _ => return Err(VaultError::InvalidFormat),
        };
        if year == 0 || day == 0 || day > days {
            return Err(VaultError::InvalidFormat);
        }
        Ok(Self { year, month, day })
    }
}

/// No Debug/Display on the profile to prevent accidental secret-bearing logs.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Profile {
    pub legal_name: String,
    pub birth_date: Date,
    pub shipping_address: String,
}

impl Profile {
    /// ONLY synthetic fixture data, never an actual person.
    #[must_use]
    pub fn fictitious() -> Self {
        Self {
            legal_name: "Alex Example".to_owned(),
            birth_date: Date {
                year: 2000,
                month: 4,
                day: 12,
            },
            shipping_address: "Calle Ficticia 123".to_owned(),
        }
    }

    /// Locally computed assertion. NOT a zero-knowledge proof and NOT an
    /// issuer-verified age credential. Leap-day birthdays use March 1.
    pub fn age_over_18(&self, today: Date) -> Result<bool, VaultError> {
        Date::new(today.year, today.month, today.day)?;
        let born = Date::new(
            self.birth_date.year,
            self.birth_date.month,
            self.birth_date.day,
        )?;
        let threshold = match today.year.checked_sub(18) {
            Some(y) => y,
            None => return Ok(false),
        };
        let (birthday_month, birthday_day) =
            if born.month == 2 && born.day == 29 && !is_leap_year(today.year) {
                (3, 1)
            } else {
                (born.month, born.day)
            };
        Ok(born.year < threshold
            || (born.year == threshold
                && (today.month, today.day) >= (birthday_month, birthday_day)))
    }
}

fn is_leap_year(year: u16) -> bool {
    year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}

fn derive_key(
    passphrase: &str,
    salt: &[u8; SALT_LEN],
) -> Result<Zeroizing<[u8; KEY_LEN]>, VaultError> {
    if passphrase.len() < 12 {
        return Err(VaultError::WeakPassphrase);
    }
    let params = Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_ITERATIONS,
        ARGON2_LANES,
        Some(KEY_LEN),
    )
    .map_err(|_| VaultError::Kdf)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    argon
        .hash_password_into(passphrase.as_bytes(), salt, &mut *key)
        .map_err(|_| VaultError::Kdf)?;
    Ok(key)
}

fn aes_key(bytes: &[u8]) -> Result<LessSafeKey, VaultError> {
    let unbound = UnboundKey::new(&aead::AES_256_GCM, bytes).map_err(|_| VaultError::Encryption)?;
    Ok(LessSafeKey::new(unbound))
}

/// Encrypts into a self-contained, authenticated binary envelope.
/// Its public header (magic, format, salt, nonce) is AEAD-authenticated.
pub fn seal(profile: &Profile, passphrase: &str) -> Result<Vec<u8>, VaultError> {
    // Generate both values with the crypto RNG; no fixed-value salt/nonce.
    let rng = rand::SystemRandom::new();
    let salt: [u8; SALT_LEN] = rand::generate(&rng)
        .map_err(|_| VaultError::Random)?
        .expose();
    let nonce: [u8; NONCE_LEN] = rand::generate(&rng)
        .map_err(|_| VaultError::Random)?
        .expose();

    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(MAGIC);
    header.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
    header.extend_from_slice(&salt);
    header.extend_from_slice(&nonce);

    let mut plaintext =
        Zeroizing::new(serde_json::to_vec(profile).map_err(|_| VaultError::Encoding)?);
    if plaintext.len() > MAX_VAULT_BYTES - HEADER_LEN - TAG_LEN {
        return Err(VaultError::TooLarge);
    }

    let key_material = derive_key(passphrase, &salt)?;
    let key = aes_key(&*key_material)?;
    let nonce = Nonce::try_assume_unique_for_key(&nonce).map_err(|_| VaultError::Encryption)?;
    key.seal_in_place_append_tag(nonce, Aad::from(header.as_slice()), &mut *plaintext)
        .map_err(|_| VaultError::Encryption)?;
    header.extend_from_slice(&plaintext);
    Ok(header)
}

/// Returns only authenticated plaintext. Wrong password and tampering have the
/// same error to avoid leaking which cause occurred.
pub fn open(blob: &[u8], passphrase: &str) -> Result<Profile, VaultError> {
    if blob.len() > MAX_VAULT_BYTES {
        return Err(VaultError::TooLarge);
    }
    if blob.len() < HEADER_LEN + TAG_LEN
        || &blob[..8] != MAGIC
        || &blob[8..10] != FORMAT_VERSION.to_be_bytes().as_slice()
    {
        return Err(VaultError::InvalidFormat);
    }
    // The salt comes from the file header; authentication is checked by AEAD.
    let salt: &[u8; SALT_LEN] = (&blob[10..10 + SALT_LEN])
        .try_into()
        .map_err(|_| VaultError::InvalidFormat)?;
    let key_material = derive_key(passphrase, salt)?;
    let key = aes_key(&*key_material)?;
    let nonce = Nonce::try_assume_unique_for_key(&blob[10 + SALT_LEN..HEADER_LEN])
        .map_err(|_| VaultError::InvalidFormat)?;
    let mut ciphertext = Zeroizing::new(blob[HEADER_LEN..].to_vec());
    let decrypted = key
        .open_in_place(nonce, Aad::from(&blob[..HEADER_LEN]), &mut ciphertext)
        .map_err(|_| VaultError::UnlockFailed)?;
    let profile: Profile = serde_json::from_slice(decrypted).map_err(|_| VaultError::Encoding)?;
    Date::new(
        profile.birth_date.year,
        profile.birth_date.month,
        profile.birth_date.day,
    )?;
    Ok(profile)
}

/// Creates a brand-new file, never overwrites an existing vault. Unix creation
/// mode is 0600, regardless of the user's umask.
pub fn create_new(path: &Path, profile: &Profile, passphrase: &str) -> Result<(), VaultError> {
    let blob = seal(profile, passphrase)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    if let Err(e) = file.write_all(&blob).and_then(|_| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(VaultError::Io(e));
    }
    Ok(())
}

/// Loads a small encrypted vault. Rejects symlinks and overly permissive modes
/// on Unix. TOCTOU hardening is still required before real user data is used.
pub fn read_file(path: &Path, passphrase: &str) -> Result<Profile, VaultError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        return Err(VaultError::UnsafeFile);
    }
    if metadata.len() > MAX_VAULT_BYTES as u64 {
        return Err(VaultError::TooLarge);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(VaultError::UnsafeFile);
        }
    }
    let mut file = OpenOptions::new().read(true).open(path)?;
    // Validate the actual opened file, not only the path inspected earlier.
    // This reduces the symlink/replace race between symlink_metadata and open.
    let opened_metadata = file.metadata()?;
    if !opened_metadata.is_file() {
        return Err(VaultError::UnsafeFile);
    }
    if opened_metadata.len() > MAX_VAULT_BYTES as u64 {
        return Err(VaultError::TooLarge);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if opened_metadata.permissions().mode() & 0o077 != 0
            || opened_metadata.dev() != metadata.dev()
            || opened_metadata.ino() != metadata.ino()
        {
            return Err(VaultError::UnsafeFile);
        }
    }
    let mut blob = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take((MAX_VAULT_BYTES + 1) as u64)
        .read_to_end(&mut blob)?;
    open(&blob, passphrase)
}

#[cfg(test)]
mod tests {
    use super::*;
    const PASS: &str = "fixture-password-only-1234";

    #[test]
    fn encrypted_roundtrip() {
        let profile = Profile::fictitious();
        let ciphertext = seal(&profile, PASS).expect("encrypt");
        let decrypted = open(&ciphertext, PASS).expect("decrypt");
        assert!(profile == decrypted);
    }

    #[test]
    fn plaintext_is_not_in_file() {
        let bytes = seal(&Profile::fictitious(), PASS).expect("seal");
        assert!(
            !bytes
                .windows(b"Alex Example".len())
                .any(|w| w == b"Alex Example")
        );
        assert!(
            !bytes
                .windows(b"Calle Ficticia".len())
                .any(|w| w == b"Calle Ficticia")
        );
    }

    #[test]
    fn incorrect_password_fails() {
        let blob = seal(&Profile::fictitious(), PASS).expect("seal");
        assert!(matches!(
            open(&blob, "wrong-passphrase-1234"),
            Err(VaultError::UnlockFailed)
        ));
    }

    #[test]
    fn modified_ciphertext_is_rejected() {
        let mut blob = seal(&Profile::fictitious(), PASS).expect("seal");
        let last = blob.len() - 1;
        blob[last] ^= 0x01;
        assert!(matches!(open(&blob, PASS), Err(VaultError::UnlockFailed)));
    }

    #[test]
    fn altered_header_is_rejected() {
        let mut blob = seal(&Profile::fictitious(), PASS).expect("seal");
        blob[HEADER_LEN - 1] ^= 1; // nonce in authenticated header
        assert!(matches!(open(&blob, PASS), Err(VaultError::UnlockFailed)));
    }

    #[test]
    fn modified_salt_is_rejected() {
        let mut blob = seal(&Profile::fictitious(), PASS).expect("seal");
        blob[10] ^= 1;
        assert!(matches!(open(&blob, PASS), Err(VaultError::UnlockFailed)));
    }

    #[test]
    fn distinct_encryptions_use_distinct_salts_and_nonces() {
        let a = seal(&Profile::fictitious(), PASS).expect("a");
        let b = seal(&Profile::fictitious(), PASS).expect("b");
        assert_ne!(a, b);
        assert_ne!(&a[10..10 + SALT_LEN], &b[10..10 + SALT_LEN]);
        assert_ne!(&a[10 + SALT_LEN..HEADER_LEN], &b[10 + SALT_LEN..HEADER_LEN],);
    }

    #[test]
    fn rejects_weak_password_and_malformed_file() {
        assert!(matches!(
            seal(&Profile::fictitious(), "short"),
            Err(VaultError::WeakPassphrase)
        ));
        assert!(matches!(
            open(b"junk", PASS),
            Err(VaultError::InvalidFormat)
        ));
    }

    #[test]
    fn age_boundary() {
        let mut profile = Profile::fictitious();
        profile.birth_date = Date::new(2008, 10, 9).expect("date");
        assert!(
            !profile
                .age_over_18(Date::new(2026, 10, 8).expect("date"))
                .expect("check")
        );
        profile.birth_date = Date::new(2008, 10, 8).expect("date");
        assert!(
            profile
                .age_over_18(Date::new(2026, 10, 8).expect("date"))
                .expect("check")
        );
    }
}

#[cfg(test)]
mod file_tests {
    use super::*;

    #[test]
    fn disk_roundtrip_does_not_overwrite() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("fixture.vault");
        let expected = Profile::fictitious();
        create_new(&path, &expected, "fixture-password-only-1234").expect("create");
        let restored = read_file(&path, "fixture-password-only-1234").expect("read");
        assert!(restored == expected);
        assert!(
            matches!(create_new(&path, &expected, "fixture-password-only-1234"),
            Err(VaultError::Io(error)) if error.kind() == std::io::ErrorKind::AlreadyExists)
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).expect("metadata").permissions().mode();
            assert_eq!(mode & 0o077, 0);
        }
    }

    #[test]
    #[cfg(unix)]
    fn symlinks_and_public_file_permissions_are_rejected() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("fixture.vault");
        let linked = dir.path().join("linked.vault");
        create_new(&path, &Profile::fictitious(), "fixture-password-only-1234").expect("create");
        symlink(&path, &linked).expect("symlink");
        assert!(matches!(
            read_file(&linked, "fixture-password-only-1234"),
            Err(VaultError::UnsafeFile)
        ));
        let mut perms = fs::metadata(&path).expect("metadata").permissions();
        perms.set_mode(0o644);
        fs::set_permissions(&path, perms).expect("chmod");
        assert!(matches!(
            read_file(&path, "fixture-password-only-1234"),
            Err(VaultError::UnsafeFile)
        ));
    }
}
