//! Separate, versioned encrypted envelope for *demo* service signing keys.
//!
//! The profile vault and the signing-key vault use different magic bytes
//! inside authenticated data.  Neither format is a production key manager.

use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::Path,
};

use aws_lc_rs::{
    aead::{Aad, Nonce},
    rand,
};
use zeroize::Zeroizing;

use crate::{MAX_VAULT_BYTES, VaultError, aes_key, derive_key};

const MAGIC: &[u8; 8] = b"AITKEY01";
const VERSION: u16 = 1;
const SALT_SIZE: usize = 16;
const NONCE_SIZE: usize = 12;
const TAG_SIZE: usize = 16;
const HEADER_SIZE: usize = 8 + 2 + SALT_SIZE + NONCE_SIZE;

/// Ciphertext and authenticated header.  PKCS#8 only ever appears within the
/// encrypted payload; never serialize it separately to disk.
pub fn encrypt(payload: &[u8], passphrase: &str) -> Result<Vec<u8>, VaultError> {
    if payload.len() > MAX_VAULT_BYTES - HEADER_SIZE - TAG_SIZE {
        return Err(VaultError::TooLarge);
    }
    let rng = rand::SystemRandom::new();
    let salt: [u8; SALT_SIZE] = rand::generate(&rng)
        .map_err(|_| VaultError::Random)?
        .expose();
    let nonce_bytes: [u8; NONCE_SIZE] = rand::generate(&rng)
        .map_err(|_| VaultError::Random)?
        .expose();

    let mut header = Vec::with_capacity(HEADER_SIZE + payload.len() + TAG_SIZE);
    header.extend_from_slice(MAGIC);
    header.extend_from_slice(&VERSION.to_be_bytes());
    header.extend_from_slice(&salt);
    header.extend_from_slice(&nonce_bytes);

    let derived = derive_key(passphrase, &salt)?;
    let key = aes_key(&derived[..])?;
    let nonce =
        Nonce::try_assume_unique_for_key(&nonce_bytes).map_err(|_| VaultError::Encryption)?;
    let mut data = Zeroizing::new(Vec::with_capacity(payload.len() + TAG_SIZE));
    data.extend_from_slice(payload);
    key.seal_in_place_append_tag(nonce, Aad::from(header.as_slice()), &mut *data)
        .map_err(|_| VaultError::Encryption)?;
    header.extend_from_slice(&data);
    Ok(header)
}

/// Returns secret bytes zeroized on drop. The salt and nonce are public but
/// authenticated; a wrong passphrase or changed ciphertext fails closed.
pub fn decrypt(blob: &[u8], passphrase: &str) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    if blob.len() > MAX_VAULT_BYTES {
        return Err(VaultError::TooLarge);
    }
    if blob.len() < HEADER_SIZE + TAG_SIZE
        || &blob[..8] != MAGIC
        || &blob[8..10] != VERSION.to_be_bytes().as_slice()
    {
        return Err(VaultError::InvalidFormat);
    }
    let salt: &[u8; SALT_SIZE] = blob[10..10 + SALT_SIZE]
        .try_into()
        .map_err(|_| VaultError::InvalidFormat)?;
    let derived = derive_key(passphrase, salt)?;
    let key = aes_key(&derived[..])?;
    let nonce = Nonce::try_assume_unique_for_key(&blob[10 + SALT_SIZE..HEADER_SIZE])
        .map_err(|_| VaultError::InvalidFormat)?;
    let mut ciphertext = Zeroizing::new(blob[HEADER_SIZE..].to_vec());
    let plaintext = key
        .open_in_place(nonce, Aad::from(&blob[..HEADER_SIZE]), &mut ciphertext)
        .map_err(|_| VaultError::UnlockFailed)?;
    let plaintext_len = plaintext.len();
    ciphertext.truncate(plaintext_len);
    Ok(ciphertext)
}

/// Creates with mode 0600 (Unix) and refuses to replace an existing path.
pub fn create_new(path: &Path, payload: &[u8], passphrase: &str) -> Result<(), VaultError> {
    let envelope = encrypt(payload, passphrase)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    if let Err(error) = file.write_all(&envelope).and_then(|_| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(VaultError::Io(error));
    }
    Ok(())
}

/// Reads only from a private regular file and re-checks the opened inode.
/// Rejects symbolic links, oversized files and world/group-readable files.
pub fn read(path: &Path, passphrase: &str) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let before = fs::symlink_metadata(path)?;
    if !before.is_file() {
        return Err(VaultError::UnsafeFile);
    }
    if before.len() > MAX_VAULT_BYTES as u64 {
        return Err(VaultError::TooLarge);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if before.permissions().mode() & 0o077 != 0 {
            return Err(VaultError::UnsafeFile);
        }
    }
    let mut file = OpenOptions::new().read(true).open(path)?;
    let opened = file.metadata()?;
    if !opened.is_file() {
        return Err(VaultError::UnsafeFile);
    }
    if opened.len() > MAX_VAULT_BYTES as u64 {
        return Err(VaultError::TooLarge);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if opened.permissions().mode() & 0o077 != 0
            || opened.dev() != before.dev()
            || opened.ino() != before.ino()
        {
            return Err(VaultError::UnsafeFile);
        }
    }
    let mut envelope = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take((MAX_VAULT_BYTES + 1) as u64)
        .read_to_end(&mut envelope)?;
    decrypt(&envelope, passphrase)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASS: &str = "fixture-passphrase-12345";

    #[test]
    fn secret_roundtrip_and_integrity() {
        let a = encrypt(b"fixture-key-secret", PASS).expect("encrypt");
        let b = encrypt(b"fixture-key-secret", PASS).expect("encrypt");
        assert_ne!(&a[10..26], &b[10..26]);
        assert_ne!(&a[26..38], &b[26..38]);
        assert!(!a.windows(7).any(|piece| piece == b"fixture"));
        assert_eq!(
            decrypt(&a, PASS).expect("decrypt").as_slice(),
            b"fixture-key-secret"
        );
        let mut damaged = a.clone();
        let last = damaged.len() - 1;
        damaged[last] ^= 1;
        assert!(matches!(
            decrypt(&damaged, PASS),
            Err(VaultError::UnlockFailed)
        ));
        assert!(matches!(
            decrypt(&a, "incorrect-passphrase-123"),
            Err(VaultError::UnlockFailed)
        ));
        assert!(matches!(
            decrypt(b"invalid", PASS),
            Err(VaultError::InvalidFormat)
        ));
        // Profile and key material must never share an encryption domain.
        let profile = crate::seal(&crate::Profile::fictitious(), PASS).expect("profile");
        assert!(matches!(
            decrypt(&profile, PASS),
            Err(VaultError::InvalidFormat)
        ));
        assert!(matches!(
            crate::open(&a, PASS),
            Err(VaultError::InvalidFormat)
        ));
    }

    #[test]
    fn refuses_existing_file_and_insecure_permissions() {
        let tmp = tempfile::tempdir().expect("dir");
        let file = tmp.path().join("keys.aitk");
        create_new(&file, b"fixture", PASS).expect("create");
        assert!(create_new(&file, b"fixture", PASS).is_err());
        assert_eq!(read(&file, PASS).expect("read").as_slice(), b"fixture");
        #[cfg(unix)]
        {
            use std::os::unix::fs::{PermissionsExt, symlink};
            let link = tmp.path().join("link");
            symlink(&file, &link).expect("symlink");
            assert!(matches!(read(&link, PASS), Err(VaultError::UnsafeFile)));
            let mut permissions = fs::metadata(&file).expect("metadata").permissions();
            permissions.set_mode(0o644);
            fs::set_permissions(&file, permissions).expect("chmod");
            assert!(matches!(read(&file, PASS), Err(VaultError::UnsafeFile)));
        }
    }
}
