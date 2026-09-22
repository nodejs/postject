use lief_ffi as ffi;

/// This structure represents the current host.
pub struct Host {}

impl Host {
    /// The machine hostname
    pub fn name() -> String {
        ffi::runtime_Host::name().to_string()
    }

    /// The user home dir (e.g. `/home/romain` or `C:\Users\romain`)
    pub fn home_dir() -> String {
        ffi::runtime_Host::home_dir().to_string()
    }

    /// Temporary directory.
    ///
    /// This function looks at the environment variables to determine the
    /// suitable temp directory (e.g. `TEMP`, `TMPDIR`)
    pub fn tmp_dir() -> String {
        ffi::runtime_Host::tmp_dir().to_string()
    }

    /// The directory to store user-specific configuration
    pub fn config_dir() -> String {
        ffi::runtime_Host::config_dir().to_string()
    }

    /// The directory where software should store their cache files
    /// (e.g. `$HOME/.cache`)
    pub fn cache_dir() -> String {
        ffi::runtime_Host::cache_dir().to_string()
    }
}
