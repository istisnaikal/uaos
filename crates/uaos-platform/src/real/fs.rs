// SPDX-License-Identifier: Apache-2.0

//! The operating system's filesystem.

use std::fs::{File, OpenOptions, TryLockError};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::fs::{AppendFile, Fs, FsError, LockGuard, temp_sibling};

/// `std::fs`-backed implementation of [`Fs`].
#[derive(Debug, Default)]
pub struct OsFs;

#[derive(Debug)]
struct OsAppendFile(File);

#[allow(clippy::disallowed_methods, reason = "uaos-platform is the filesystem owner (D15)")]
impl AppendFile for OsAppendFile {
    fn append(&mut self, bytes: &[u8]) -> Result<(), FsError> {
        self.0.write_all(bytes).map_err(|e| FsError::from_io("append", &e))
    }

    fn sync_data(&mut self) -> Result<(), FsError> {
        // Any flush failure is reported as SyncFailed, whatever its OS error kind: the caller's
        // recovery (rewrite unflushed records to a new segment) does not depend on the cause.
        self.0.sync_data().map_err(|_| FsError::SyncFailed { op: "sync_data" })
    }

    fn os_len(&self) -> Result<u64, FsError> {
        self.0
            .metadata()
            .map(|m| m.len())
            .map_err(|e| FsError::from_io("os_len", &e))
    }
}

/// Holds the locked file open; the OS releases the lock when the handle closes, including when
/// the process dies, so a crashed daemon never leaves a stale lock behind.
#[derive(Debug)]
struct OsLockGuard(#[allow(dead_code, reason = "held only for its Drop, which releases the lock")] File);

impl LockGuard for OsLockGuard {}

#[allow(clippy::disallowed_methods, reason = "uaos-platform is the filesystem owner (D15)")]
impl Fs for OsFs {
    fn create_dir_all(&self, path: &Path) -> Result<(), FsError> {
        std::fs::create_dir_all(path).map_err(|e| FsError::from_io("create_dir_all", &e))
    }

    fn open_append(&self, path: &Path) -> Result<Box<dyn AppendFile>, FsError> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| FsError::from_io("open_append", &e))?;
        Ok(Box::new(OsAppendFile(file)))
    }

    fn read(&self, path: &Path) -> Result<Vec<u8>, FsError> {
        std::fs::read(path).map_err(|e| FsError::from_io("read", &e))
    }

    fn list_dir(&self, path: &Path) -> Result<Vec<PathBuf>, FsError> {
        let mut out = Vec::new();
        for entry in std::fs::read_dir(path).map_err(|e| FsError::from_io("list_dir", &e))? {
            out.push(entry.map_err(|e| FsError::from_io("list_dir", &e))?.path());
        }
        out.sort();
        Ok(out)
    }

    fn rename(&self, from: &Path, to: &Path) -> Result<(), FsError> {
        std::fs::rename(from, to).map_err(|e| FsError::from_io("rename", &e))
    }

    fn remove_file(&self, path: &Path) -> Result<(), FsError> {
        std::fs::remove_file(path).map_err(|e| FsError::from_io("remove_file", &e))
    }

    #[cfg(unix)]
    fn sync_dir(&self, path: &Path) -> Result<(), FsError> {
        File::open(path)
            .and_then(|dir| dir.sync_all())
            .map_err(|_| FsError::SyncFailed { op: "sync_dir" })
    }

    #[cfg(not(unix))]
    fn sync_dir(&self, path: &Path) -> Result<(), FsError> {
        // NTFS journals directory metadata; there is no portable way (and no need) to flush a
        // directory handle on Windows. Confirm the directory exists so callers get NotFound.
        std::fs::metadata(path)
            .map(|_| ())
            .map_err(|e| FsError::from_io("sync_dir", &e))
    }

    fn write_atomic(&self, path: &Path, bytes: &[u8]) -> Result<(), FsError> {
        let tmp = temp_sibling(path);
        let result = (|| {
            let mut file = File::create(&tmp).map_err(|e| FsError::from_io("write_atomic", &e))?;
            file.write_all(bytes)
                .map_err(|e| FsError::from_io("write_atomic", &e))?;
            file.sync_data()
                .map_err(|_| FsError::SyncFailed { op: "write_atomic" })?;
            drop(file);
            std::fs::rename(&tmp, path).map_err(|e| FsError::from_io("write_atomic", &e))?;
            match path.parent() {
                Some(parent) if !parent.as_os_str().is_empty() => self.sync_dir(parent),
                _ => Ok(()),
            }
        })();
        if result.is_err() {
            // Best effort: never leave a half-written temporary behind. The original `path` is
            // untouched either way. The removal error is irrelevant to the reported failure.
            let _cleanup_result = std::fs::remove_file(&tmp);
        }
        result
    }

    fn try_lock_exclusive(&self, path: &Path) -> Result<Box<dyn LockGuard>, FsError> {
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(path)
            .map_err(|e| FsError::from_io("lock", &e))?;
        match file.try_lock() {
            Ok(()) => Ok(Box::new(OsLockGuard(file))),
            Err(TryLockError::WouldBlock) => Err(FsError::Locked { op: "lock" }),
            Err(TryLockError::Error(e)) => Err(FsError::from_io("lock", &e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A unique scratch directory under the OS temp dir, removed on drop.
    struct Scratch(PathBuf);

    impl Scratch {
        #[allow(clippy::disallowed_methods, reason = "test scaffolding")]
        fn new(tag: &str) -> Self {
            let unique = format!(
                "uaos-platform-{tag}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            )
            .replace(['(', ')'], "");
            let dir = std::env::temp_dir().join(unique);
            let _stale = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _cleanup = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn conforms() {
        let scratch = Scratch::new("conform");
        crate::fs::conformance::run(&OsFs, &scratch.0);
    }

    #[test]
    fn write_atomic_leaves_no_temporary_on_failure() {
        let scratch = Scratch::new("atomic");
        // Parent directory does not exist: the write must fail and leave nothing behind.
        let target = scratch.0.join("missing").join("MANIFEST");
        assert!(OsFs.write_atomic(&target, b"x").is_err());
        assert!(OsFs.read(&temp_sibling(&target)).is_err());
    }
}
