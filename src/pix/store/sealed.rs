//! Password-derived encryption at rest, shared by the PIX stores.
//!
//! Both PIX databases hold material whose exposure is spending authority: the recovery store
//! keeps recovered deposit keys, the Curvy state store keeps the node's spender identity and
//! its scan secrets. A `0600` file mode (see [`super::private_db`]) stops other local users, but
//! not a backup or a copied disk. For those, every such value is sealed under a key derived from
//! a configured password:
//!
//! ```text
//! Config password  ──→  scrypt(password, per-db salt)  ──→  256-bit key
//!                                                               │
//!                 Per-value random nonce (12) ──────────────────┤  ChaCha20Poly1305
//!                 Associated data: the value's slot ────────────┤
//!                                                               ▼
//!                 nonce (12) || ciphertext || tag (16)
//! ```
//!
//! **Key derivation.** scrypt (RFC 7914) with the recommended parameters (log₂ N = 17, r = 8,
//! p = 1) over a random 16-byte salt the database stores next to its data. The derived key never
//! leaves process memory.
//!
//! **Password check.** A known plaintext sealed under the key is stored with the salt, and every
//! open checks it: a rotated or mistyped password is refused up front rather than leaving the
//! store looking empty. A database that predates the verifier adopts the password of its next
//! open.
//!
//! **Slot binding.** The associated data is the slot a value is filed under — a table key, or a
//! fixed tag for a singleton — so a sealed value moved to another slot fails to open instead of
//! decrypting as that slot's secret. The verifier's own slot is one no value can occupy.
//!
//! ## Threat model
//!
//! Protects against an attacker who obtains read access to the database file: a backup, an
//! exfiltrated copy, a stolen disk. Without the password they cannot derive the key, and
//! without the key they cannot open any value. It does **not** protect against an attacker who
//! also has the password — which lives in the node's environment, readable by the same user and
//! by root through `/proc/<pid>/environ` — or who can execute code as the node process.

use std::fmt;

use chacha20poly1305::{
    ChaCha20Poly1305, Key, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use hopr_api::types::crypto_random::random_bytes;
use redb::{ReadableTable, TableDefinition};
use scrypt::{Params as ScryptParams, scrypt};

const NONCE_SIZE: usize = 12;
const TAG_SIZE: usize = 16;
const SALT_SIZE: usize = 16;
/// A sealed 32-byte value: the size of the verifier record, and of every fixed-size secret.
pub(crate) const SEALED_32_SIZE: usize = NONCE_SIZE + 32 + TAG_SIZE;

/// Why a value could not be sealed or opened.
#[derive(Debug, thiserror::Error)]
pub(crate) enum SealError {
    #[error("encryption error")]
    Encryption,
    #[error("decryption error")]
    Decryption,
}

/// The derived key, and the two things one does with it.
#[derive(Clone)]
pub(crate) struct Sealer {
    key: [u8; 32],
}

impl fmt::Debug for Sealer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Sealer(..)")
    }
}

impl Sealer {
    fn derive(password: &str, salt: &[u8; SALT_SIZE]) -> Self {
        let mut key = [0u8; 32];
        scrypt(password.as_bytes(), salt, &ScryptParams::RECOMMENDED, &mut key)
            .expect("scrypt with 32-byte output must succeed");
        Self { key }
    }

    /// A fresh random key, for stores that never touch a file and so never need a password.
    #[cfg(test)]
    pub(crate) fn random() -> Self {
        Self {
            key: random_bytes::<32>(),
        }
    }

    /// Seals `plaintext` into `nonce || ciphertext || tag`, bound to `aad`: the slot the value
    /// is filed under, so a value moved elsewhere no longer opens.
    pub(crate) fn seal(&self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, SealError> {
        let cipher = ChaCha20Poly1305::new(&Key::from(self.key));
        let nonce = random_bytes::<NONCE_SIZE>();
        let ciphertext = cipher
            .encrypt(&Nonce::from(nonce), Payload { msg: plaintext, aad })
            .map_err(|_| SealError::Encryption)?;
        let mut out = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Opens a value sealed by [`Self::seal`] under the same `aad`.
    pub(crate) fn open(&self, aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>, SealError> {
        let (nonce, ciphertext) = sealed.split_at_checked(NONCE_SIZE).ok_or(SealError::Decryption)?;
        let nonce: [u8; NONCE_SIZE] = nonce.try_into().map_err(|_| SealError::Decryption)?;
        ChaCha20Poly1305::new(&Key::from(self.key))
            .decrypt(&Nonce::from(nonce), Payload { msg: ciphertext, aad })
            .map_err(|_| SealError::Decryption)
    }
}

/// Where a database keeps the salt its key is derived from and the record its password is
/// checked against.
pub(crate) struct PasswordSlots {
    pub(crate) salt: TableDefinition<'static, u8, [u8; SALT_SIZE]>,
    pub(crate) verifier: TableDefinition<'static, u8, [u8; SEALED_32_SIZE]>,
    /// Known plaintext sealed into the verifier record.
    pub(crate) verifier_plaintext: [u8; 32],
    /// The verifier's slot: associated data no stored value can be filed under.
    pub(crate) verifier_aad: &'static [u8],
}

/// Why [`PasswordSlots::unlock`] produced no key.
#[derive(Debug, thiserror::Error)]
pub(crate) enum UnlockError {
    #[error("database error: {0}")]
    Database(#[from] redb::Error),
    #[error("the configured password does not match this store")]
    WrongPassword,
    #[error(transparent)]
    Seal(#[from] SealError),
}

macro_rules! unlock_error_from_redb {
    ($($error:ty),*) => {$(
        impl From<$error> for UnlockError {
            fn from(error: $error) -> Self {
                Self::Database(error.into())
            }
        }
    )*};
}
unlock_error_from_redb!(
    redb::TransactionError,
    redb::TableError,
    redb::StorageError,
    redb::CommitError
);

impl PasswordSlots {
    /// Derives the key for `db` from `password`. The first open of a database writes its salt,
    /// and a database without a verifier adopts this password; any later open must present the
    /// same one or fails with [`UnlockError::WrongPassword`].
    pub(crate) fn unlock(&self, db: &redb::Database, password: &str) -> Result<Sealer, UnlockError> {
        let write = db.begin_write()?;
        let sealer = {
            let mut salts = write.open_table(self.salt)?;
            // Copied out so the access guard drops before the insert.
            let existing: Option<[u8; SALT_SIZE]> = salts.get(&0u8)?.map(|guard| guard.value());
            let salt = match existing {
                Some(salt) => salt,
                None => {
                    let salt = random_bytes::<SALT_SIZE>();
                    salts.insert(&0u8, salt)?;
                    salt
                }
            };
            Sealer::derive(password, &salt)
        };
        {
            let mut verifiers = write.open_table(self.verifier)?;
            let existing: Option<[u8; SEALED_32_SIZE]> = verifiers.get(&0u8)?.map(|guard| guard.value());
            match existing {
                Some(stored) => {
                    let plaintext = sealer
                        .open(self.verifier_aad, &stored)
                        .map_err(|_| UnlockError::WrongPassword)?;
                    if plaintext != self.verifier_plaintext {
                        return Err(UnlockError::WrongPassword);
                    }
                }
                None => {
                    let sealed: [u8; SEALED_32_SIZE] = sealer
                        .seal(self.verifier_aad, &self.verifier_plaintext)?
                        .try_into()
                        .map_err(|_| SealError::Encryption)?;
                    verifiers.insert(&0u8, sealed)?;
                }
            }
        }
        write.commit()?;
        Ok(sealer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SLOTS: PasswordSlots = PasswordSlots {
        salt: TableDefinition::new("test_salt"),
        verifier: TableDefinition::new("test_verifier"),
        verifier_plaintext: *b"sealed-module-test-verifier-text",
        verifier_aad: b"verifier",
    };

    fn in_memory() -> redb::Database {
        redb::Database::builder()
            .create_with_backend(redb::backends::InMemoryBackend::new())
            .unwrap()
    }

    #[test]
    fn seal_round_trips_and_binds_to_the_slot() {
        let sealer = Sealer::random();
        let sealed = sealer.seal(b"slot-a", b"hello").unwrap();
        assert_eq!(sealed.len(), NONCE_SIZE + 5 + TAG_SIZE);
        assert_eq!(sealer.open(b"slot-a", &sealed).unwrap(), b"hello");
        assert!(matches!(sealer.open(b"slot-b", &sealed), Err(SealError::Decryption)));
        let mut tampered = sealed.clone();
        tampered[NONCE_SIZE] ^= 1;
        assert!(matches!(sealer.open(b"slot-a", &tampered), Err(SealError::Decryption)));
        assert!(matches!(
            sealer.open(b"slot-a", &sealed[..NONCE_SIZE - 1]),
            Err(SealError::Decryption)
        ));
        assert!(matches!(
            Sealer::random().open(b"slot-a", &sealed),
            Err(SealError::Decryption)
        ));
    }

    #[test]
    fn unlock_adopts_the_first_password_and_refuses_others() {
        let db = in_memory();
        let first = SLOTS.unlock(&db, "one").unwrap();
        let again = SLOTS.unlock(&db, "one").unwrap();
        let sealed = first.seal(b"x", b"payload").unwrap();
        assert_eq!(again.open(b"x", &sealed).unwrap(), b"payload");
        assert!(matches!(SLOTS.unlock(&db, "two"), Err(UnlockError::WrongPassword)));
    }

    #[test]
    fn unlock_adopts_the_password_of_a_database_without_a_verifier() {
        let db = in_memory();
        SLOTS.unlock(&db, "one").unwrap();
        {
            let write = db.begin_write().unwrap();
            write.delete_table(SLOTS.verifier).unwrap();
            write.commit().unwrap();
        }
        SLOTS.unlock(&db, "two").unwrap();
        assert!(matches!(SLOTS.unlock(&db, "one"), Err(UnlockError::WrongPassword)));
    }
}
