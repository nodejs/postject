use lief_ffi as ffi;

/// This structure exposes OSX-specific API for the current process.
pub struct Process {}

impl Process {
    /// Return the version of dyld for the current process
    pub fn dyld_version() -> String {
        ffi::runtime_osx_Process::dyld_version().to_string()
    }
}
