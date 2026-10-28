use std::path::PathBuf;

/// Locates the `locksmith` CLI executable across standard installation directories,
/// environment variables, and adjacent paths.
///
/// Security:
/// - Any `LOCKSMITH_BIN` environment override MUST be an absolute path and must exist as a regular file.
/// - Relative paths, directories, and non-existent files are rejected to prevent local binary hijacking.
pub fn find_locksmith_binary() -> PathBuf {
    // 1. Check explicit LOCKSMITH_BIN environment variable override
    if let Ok(p) = std::env::var("LOCKSMITH_BIN") {
        let trimmed = p.trim();
        if !trimmed.is_empty() {
            let path = PathBuf::from(trimmed);
            // Require absolute path and ensure it is an existing file (not a directory or relative traversal)
            if path.is_absolute() && path.is_file() {
                return path;
            }
        }
    }

    // 2. Standard system locations
    let system_candidates = [
        "/opt/homebrew/bin/locksmith",
        "/usr/local/bin/locksmith",
        "/usr/bin/locksmith",
    ];
    for c in &system_candidates {
        let p = PathBuf::from(c);
        if p.is_file() {
            return p;
        }
    }

    // 3. User home locations (~/.local/bin, ~/go/bin, ~/.cargo/bin, ~/bin)
    if let Ok(home) = std::env::var("HOME") {
        let user_candidates = [
            PathBuf::from(&home).join(".local/bin/locksmith"),
            PathBuf::from(&home).join("go/bin/locksmith"),
            PathBuf::from(&home).join(".cargo/bin/locksmith"),
            PathBuf::from(&home).join("bin/locksmith"),
        ];
        for p in &user_candidates {
            if p.is_file() {
                return p.clone();
            }
        }
    }

    // 4. Windows standard install locations
    #[cfg(target_os = "windows")]
    {
        if let Ok(appdata) = std::env::var("LOCALAPPDATA") {
            let p = PathBuf::from(appdata)
                .join("Programs")
                .join("Locksmith")
                .join("locksmith.exe");
            if p.is_file() {
                return p;
            }
        }
    }

    // 5. Adjacent to current running executable (e.g. bundled or dev bin)
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let adjacent = dir.join(if cfg!(target_os = "windows") {
                "locksmith.exe"
            } else {
                "locksmith"
            });
            if adjacent.is_file() {
                return adjacent;
            }
        }
    }

    // Fallback to searching PATH via default command name
    PathBuf::from(if cfg!(target_os = "windows") {
        "locksmith.exe"
    } else {
        "locksmith"
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_locksmith_binary_returns_non_empty_path() {
        let bin = find_locksmith_binary();
        assert!(!bin.as_os_str().is_empty());
    }

    #[test]
    fn test_adversarial_relative_locksmith_bin_ignored() {
        // Attempt binary hijacking via relative path
        std::env::set_var("LOCKSMITH_BIN", "./malicious_locksmith");
        let bin = find_locksmith_binary();
        assert_ne!(bin, PathBuf::from("./malicious_locksmith"));
        std::env::remove_var("LOCKSMITH_BIN");
    }

    #[test]
    fn test_adversarial_directory_locksmith_bin_ignored() {
        // Attempt injection pointing to a directory instead of a binary
        std::env::set_var("LOCKSMITH_BIN", "/tmp");
        let bin = find_locksmith_binary();
        assert_ne!(bin, PathBuf::from("/tmp"));
        std::env::remove_var("LOCKSMITH_BIN");
    }

    #[test]
    fn test_adversarial_empty_locksmith_bin_ignored() {
        std::env::set_var("LOCKSMITH_BIN", "   ");
        let bin = find_locksmith_binary();
        assert!(!bin.as_os_str().is_empty());
        std::env::remove_var("LOCKSMITH_BIN");
    }
}
