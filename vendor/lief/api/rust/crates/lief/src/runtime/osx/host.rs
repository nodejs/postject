use lief_ffi as ffi;
use std::fmt;

/// Represents a macOS version number (major.minor.patch).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Version {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl Version {
    pub fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    fn from_ffi(v: cxx::UniquePtr<ffi::runtime_osx_Host_version_t>) -> Self {
        Self {
            major: v.get_major(),
            minor: v.get_minor(),
            patch: v.get_patch(),
        }
    }

    /// macOS Big Sur (11.0)
    pub fn big_sur() -> Self {
        Self::from_ffi(ffi::runtime_osx_Host_version_t::big_sur())
    }

    /// macOS Monterey (12.0)
    pub fn monterey() -> Self {
        Self::from_ffi(ffi::runtime_osx_Host_version_t::monterey())
    }

    /// macOS Ventura (13.0)
    pub fn ventura() -> Self {
        Self::from_ffi(ffi::runtime_osx_Host_version_t::ventura())
    }

    /// macOS Sonoma (14.0)
    pub fn sonoma() -> Self {
        Self::from_ffi(ffi::runtime_osx_Host_version_t::sonoma())
    }

    /// macOS Sequoia (15.0)
    pub fn sequoia() -> Self {
        Self::from_ffi(ffi::runtime_osx_Host_version_t::sequoia())
    }

    /// macOS Tahoe (26.0)
    pub fn tahoe() -> Self {
        Self::from_ffi(ffi::runtime_osx_Host_version_t::tahoe())
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (self.major, self.minor, self.patch).cmp(&(other.major, other.minor, other.patch))
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// This structure exposes OSX-specific host information.
pub struct Host {}

impl Host {
    /// The operating system version string
    pub fn os_version_name() -> String {
        ffi::runtime_osx_Host::os_version_name().to_string()
    }

    /// The operating system version as a [`Version`]
    pub fn os_version() -> Version {
        Version::from_ffi(ffi::runtime_osx_Host_version_t::os_version())
    }

    /// Whether System Integrity Protection (SIP) is enabled on this host.
    ///
    /// This conservatively returns `true` when the status can't be determined.
    pub fn is_sip_enabled() -> bool {
        ffi::runtime_osx_Host::is_sip_enabled()
    }
}
