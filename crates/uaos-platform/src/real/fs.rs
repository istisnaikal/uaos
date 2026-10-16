// SPDX-License-Identifier: Apache-2.0

//! The operating system's filesystem.

use std::fs::{File, OpenOptions, TryLockError};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::fs::{AppendFile, Fs, FsError, LockGuard, temp_sibling};

/// `std::fs`-backed implementation of [`Fs`]. It works only on local paths: a Windows UNC path
/// (`\\host\share`, `\\?\UNC\...`) resolves its host and opens SMB to it, and a device
/// path (`\\.\...`, `\\?\GLOBALROOT\...`) reaches past the file system, so both are refused
/// with [`FsError::PermissionDenied`] before any call (review WP3.A5, round 7, M2), and so is
/// any path that starts with two separators, which Windows reads as UNC even where std parses no
/// prefix (round 13, M1). Data stays local (red line 1).
#[derive(Debug, Default)]
pub struct OsFs;

/// Refuses a path that is not on a local disk.
#[cfg_attr(
    not(windows),
    allow(
        clippy::unnecessary_wraps,
        reason = "only Windows has network and device path spellings to refuse"
    )
)]
fn local(path: &Path, op: &'static str) -> Result<(), FsError> {
    #[cfg(windows)]
    {
        use std::path::{Component, Prefix};
        let mut parts = path.components();
        // Windows reads two leading separators, in any mix of `\` and `/`, as a network path
        // even where std parses no UNC prefix (`\\host\\share`, `//host//share`): std
        // requires a non-empty server and share, the system collapses the doubled separator
        // (review WP3.A5, round 13, M1). Only a verbatim disk path may start that way, and std
        // parses that one as a prefix.
        let doubled = path
            .as_os_str()
            .as_encoded_bytes()
            .get(..2)
            .is_some_and(|start| start.iter().all(|b| *b == b'\\' || *b == b'/'));
        let refused = match parts.next() {
            Some(Component::Prefix(prefix)) => !matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_)),
            // `\??\...` names the NT object namespace (`\??\UNC\host`, devices): std does not
            // parse it as a prefix but hands it to the system unchanged (review WP3.A5, round 8, M1).
            Some(Component::RootDir) => doubled || parts.next() == Some(Component::Normal(std::ffi::OsStr::new("??"))),
            _ => doubled,
        };
        if refused {
            return Err(FsError::PermissionDenied { op });
        }
    }
    #[cfg(not(windows))]
    let _ = (path, op);
    Ok(())
}

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
        local(path, "create_dir_all")?;
        std::fs::create_dir_all(path).map_err(|e| FsError::from_io("create_dir_all", &e))
    }

    fn open_append(&self, path: &Path) -> Result<Box<dyn AppendFile>, FsError> {
        local(path, "open_append")?;
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| FsError::from_io("open_append", &e))?;
        Ok(Box::new(OsAppendFile(file)))
    }

    fn read(&self, path: &Path) -> Result<Vec<u8>, FsError> {
        local(path, "read")?;
        std::fs::read(path).map_err(|e| FsError::from_io("read", &e))
    }

    fn list_dir(&self, path: &Path) -> Result<Vec<PathBuf>, FsError> {
        local(path, "list_dir")?;
        let mut out = Vec::new();
        for entry in std::fs::read_dir(path).map_err(|e| FsError::from_io("list_dir", &e))? {
            out.push(entry.map_err(|e| FsError::from_io("list_dir", &e))?.path());
        }
        out.sort();
        Ok(out)
    }

    fn rename(&self, from: &Path, to: &Path) -> Result<(), FsError> {
        local(from, "rename")?;
        local(to, "rename")?;
        std::fs::rename(from, to).map_err(|e| FsError::from_io("rename", &e))
    }

    fn remove_file(&self, path: &Path) -> Result<(), FsError> {
        local(path, "remove_file")?;
        std::fs::remove_file(path).map_err(|e| FsError::from_io("remove_file", &e))
    }

    #[cfg(unix)]
    fn sync_dir(&self, path: &Path) -> Result<(), FsError> {
        local(path, "sync_dir")?;
        File::open(path)
            .and_then(|dir| dir.sync_all())
            .map_err(|_| FsError::SyncFailed { op: "sync_dir" })
    }

    #[cfg(not(unix))]
    fn sync_dir(&self, path: &Path) -> Result<(), FsError> {
        // NTFS journals directory metadata; there is no portable way (and no need) to flush a
        // directory handle on Windows. Confirm the directory exists so callers get NotFound.
        local(path, "sync_dir")?;
        std::fs::metadata(path)
            .map(|_| ())
            .map_err(|e| FsError::from_io("sync_dir", &e))
    }

    fn write_atomic(&self, path: &Path, bytes: &[u8]) -> Result<(), FsError> {
        local(path, "write_atomic")?;
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
        local(path, "lock")?;
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

    /// Rounds 7, 8 and 13 (M2, M1, M1): every method refuses network and device paths, in every
    /// prefix spelling, before any call; local ones pass. DOS device names in the last
    /// component (`C:\data\NUL`) are not refused: every file UAOS opens has a name UAOS chooses,
    /// and the data directory, which configuration names, is owed with M3 (review WP3.A5,
    /// round 9).
    #[cfg(windows)]
    #[test]
    fn network_and_device_paths_are_refused() {
        let refused = |r: Result<(), FsError>| matches!(r, Err(FsError::PermissionDenied { .. }));
        let scratch = Scratch::new("refused");
        let local_file = scratch.0.join("local");
        for path in [
            r"\\uaos-canary.invalid\share\x",
            r"\\?\UNC\uaos-canary.invalid\share\x",
            r"\\.\pipe\uaos-canary",
            r"\\?\GLOBALROOT\Device\uaos-canary",
            r"\??\UNC\uaos-canary.invalid\share\x",
            r"\??\GLOBALROOT\Device\Null",
            r"/??/pipe/uaos-canary",
            r"\\uaos-canary.invalid\\share\x",
            r"//uaos-canary.invalid//share/x",
            r"\/uaos-canary.invalid\\share\x",
            r"\\uaos-canary.invalid\",
        ] {
            let p = Path::new(path);
            assert!(refused(OsFs.create_dir_all(p)), "create_dir_all {path}");
            assert!(refused(OsFs.open_append(p).map(drop)), "open_append {path}");
            assert!(refused(OsFs.read(p).map(drop)), "read {path}");
            assert!(refused(OsFs.list_dir(p).map(drop)), "list_dir {path}");
            assert!(refused(OsFs.rename(p, &local_file)), "rename from {path}");
            assert!(refused(OsFs.rename(&local_file, p)), "rename to {path}");
            assert!(refused(OsFs.remove_file(p)), "remove_file {path}");
            assert!(refused(OsFs.sync_dir(p)), "sync_dir {path}");
            assert!(refused(OsFs.write_atomic(p, b"x")), "write_atomic {path}");
            assert!(refused(OsFs.try_lock_exclusive(p).map(drop)), "lock {path}");
        }
        for path in [r"C:\data", r"\\?\C:\data", "relative", r"\data", r"\x\??"] {
            assert!(local(Path::new(path), "read").is_ok(), "{path}");
        }
    }

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
        #[allow(clippy::disallowed_methods, reason = "test scaffolding")]
        fn drop(&mut self) {
            let _cleanup = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn conforms() {
        let scratch = Scratch::new("conform");
        crate::fs::conformance::run(&OsFs, &scratch.0);
    }

    /// Data directories live under user profiles such as `C:\Users\Şükrü` or `/home/ılgın`.
    /// Runs on every CI OS, whatever its code page: UAOS itself must not depend on one.
    #[test]
    fn conforms_under_non_ascii_path_with_spaces() {
        let scratch = Scratch::new("conform dir ü ş ı Ş İ");
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
