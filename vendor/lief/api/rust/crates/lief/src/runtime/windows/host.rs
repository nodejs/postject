use lief_ffi as ffi;
use std::fmt;

/// Represents a Windows version number
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Version {
    pub major: u32,
    pub minor: u32,
    pub build_number: u32,
}

impl Version {
    pub fn new(major: u32, minor: u32, build_number: u32) -> Self {
        Self {
            major,
            minor,
            build_number,
        }
    }

    fn from_ffi(v: cxx::UniquePtr<ffi::runtime_windows_Host_version_t>) -> Self {
        Self {
            major: v.get_major(),
            minor: v.get_minor(),
            build_number: v.get_build_number(),
        }
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (self.major, self.minor, self.build_number).cmp(&(
            other.major,
            other.minor,
            other.build_number,
        ))
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.build_number)
    }
}

/// This structure exposes Windows-specific host information.
pub struct Host {}

impl Host {
    /// Return the Windows version (e.g., `10.0.26200`)
    pub fn version() -> Option<Version> {
        Some(Version::from_ffi(ffi::runtime_windows_Host::version()))
            .filter(|v| v.major > 0 || v.minor > 0 || v.build_number > 0)
    }
}
