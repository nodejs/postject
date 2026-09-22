use lief_ffi as ffi;

/// This structure exposes Linux-specific API for the current process.
pub struct Process {}

impl Process {
    /// Return the content of `/proc/cmdline`
    pub fn cmdline() -> Option<String> {
        let cmdline = ffi::runtime_linux_Process::cmdline().to_string();
        if cmdline.is_empty() {
            None
        } else {
            Some(cmdline)
        }
    }

    /// Return the version of the GNU C Library (glibc) loaded in the current
    /// process (e.g. `2.39`).
    pub fn glibc_version() -> Option<String> {
        let version = ffi::runtime_linux_Process::glibc_version().to_string();
        if version.is_empty() {
            None
        } else {
            Some(version)
        }
    }
}
