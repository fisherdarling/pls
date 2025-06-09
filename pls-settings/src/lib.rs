use std::path::PathBuf;

use foundations::settings::settings;

#[settings]
pub struct Settings {
    pub scanning: ScanSettings,
    pub reporting: ReportingSettings,
}

#[settings]
pub struct ScanSettings {
    /// Top-level directories to start scanning from.
    #[serde(default = "default_roots")]
    pub roots: Vec<PathBuf>,

    /// File types to parse for certificates.
    #[serde(default = "default_file_types")]
    pub file_types: Vec<String>,

    /// Paths to ignore when scanning. Accepts glob patterns.
    #[serde(default = "default_ignore_paths")]
    pub ignore_paths: Vec<String>,

    /// Respect gitignore when scanning.
    #[serde(default = "default_respect_gitignore")]
    pub respect_gitignore: bool,
}

fn default_roots() -> Vec<PathBuf> {
    let paths: &[&str] = if cfg!(target_os = "windows") {
        &["C:\\"]
    } else if cfg!(target_os = "linux") {
        &[
            "/etc", "/home", "/opt", "/usr", "/var", "/bin", "/sbin", "/root",
        ]
    } else if cfg!(target_os = "macos") {
        &["/"]
    } else {
        &["/"]
    };

    paths.iter().map(PathBuf::from).collect()
}

fn default_file_types() -> Vec<String> {
    [
        "pem",
        "crt",
        "csr",
        "key",
        "json",
        "ca-bundle",
        "p7b",
        "p7s",
        "pfx",
        "p12",
    ]
    .map(|filetype| format!("*.{filetype}"))
    .into_iter()
    .collect()
}

fn default_ignore_paths() -> Vec<String> {
    vec![
        "**/node_modules".to_string(),
        "**/pnpm/metadata".to_string(),
        #[cfg(target_os = "macos")]
        "**/Library/Caches".to_string(),
        #[cfg(target_os = "macos")]
        "**/Library/Developer/CoreSimulator".to_string(),
        #[cfg(target_os = "macos")]
        "**/Library/Containers".to_string(),
        #[cfg(target_os = "macos")]
        "**/Applications/Xcode.app".to_string(),
    ]
}

fn default_respect_gitignore() -> bool {
    true
}

#[settings]
pub struct ReportingSettings {
    /// Determines whether to track CA certificates.
    #[serde(default = "default_track_cas")]
    pub track_cas: bool,
}

fn default_track_cas() -> bool {
    false
}
