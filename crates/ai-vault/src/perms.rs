//! File and directory permissions, per platform.
//!
//! On Unix a secret file is 0600 and its directory 0700. Windows has no mode
//! bits: a file under the user's profile is protected by the profile's ACL,
//! which is why the store lives in `%USERPROFILE%\.ai-vault` and nothing else
//! is done there. The helpers are no-ops that keep the call sites honest.

use std::fs::OpenOptions;
use std::path::Path;

/// Open a new file that only this user can read, where the OS has such a thing.
pub fn open_private(path: &Path) -> std::io::Result<std::fs::File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

/// Narrow an existing file to the owner, best effort.
pub fn restrict_file(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

/// Narrow a directory to the owner, best effort.
pub fn restrict_dir(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700));
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

/// Best-effort fsync of a directory entry, where the platform allows it.
pub fn sync_dir(dir: &Path) {
    if let Ok(handle) = std::fs::File::open(dir) {
        let _ = handle.sync_all();
    }
}
