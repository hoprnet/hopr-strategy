//! Opening on-disk `redb` databases that hold secrets.
//!
//! Both PIX stores keep material on disk that must not leak to other local users: the Curvy
//! state store holds the node's spender keys and scan secrets, and the recovery store holds
//! ciphertext plus the password verifier that an offline scrypt search would target. Both
//! therefore open their file through [`open_private_database`], which keeps the file at mode
//! `0600` instead of whatever the process umask would yield.

use std::path::Path;

/// Why [`open_private_database`] could not produce a database.
#[derive(Debug, thiserror::Error)]
pub(crate) enum PrivateDatabaseError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("database error: {0}")]
    Database(#[from] redb::DatabaseError),
}

/// Opens (or creates) the `redb` database at `path` as a file only its owner can read.
///
/// On Unix the file is created with mode `0600`, and an existing file is brought back to it
/// on the same handle `redb` goes on to use, so a database loosened by an earlier version or
/// by hand is fixed on the next open. Parent directories are not created.
pub(crate) fn open_private_database(path: impl AsRef<Path>) -> Result<redb::Database, PrivateDatabaseError> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(redb::Database::builder().create_file(file)?)
}

#[cfg(all(test, unix))]
mod tests {
    use std::{os::unix::fs::PermissionsExt, process::Command};

    use super::*;

    #[test]
    fn database_is_private() -> anyhow::Result<()> {
        const CHILD_PATH: &str = "PIX_PRIVATE_DB_PERMISSION_TEST_PATH";
        if let Some(path) = std::env::var_os(CHILD_PATH) {
            drop(open_private_database(&path)?);
            assert_eq!(std::fs::metadata(&path)?.permissions().mode() & 0o777, 0o600);
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))?;
            drop(open_private_database(&path)?);
            assert_eq!(std::fs::metadata(&path)?.permissions().mode() & 0o777, 0o600);
            return Ok(());
        }
        // Changing umask in this process would race the other tests.
        let dir = tempfile::tempdir()?;
        // The test's own path, minus the crate name the filter does not take: moving this module
        // then cannot leave the child running no test at all and the parent passing on its word.
        let (_, this_test) = concat!(module_path!(), "::database_is_private")
            .split_once("::")
            .expect("test module path has a crate prefix");
        let status = Command::new("sh")
            .args(["-c", "umask 022; exec \"$@\"", "pix-private-db-permissions"])
            .arg(std::env::current_exe()?)
            .args(["--exact", this_test])
            .env(CHILD_PATH, dir.path().join("private.redb"))
            .status()?;
        assert!(status.success());
        Ok(())
    }
}
