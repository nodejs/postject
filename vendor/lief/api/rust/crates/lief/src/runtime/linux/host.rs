use lief_ffi as ffi;

/// This structure exposes Linux-specific host information.
pub struct Host {}

impl Host {
    /// Operating system name (e.g. `Linux`)
    pub fn sys_name() -> String {
        ffi::runtime_linux_Host::sys_name().to_string()
    }

    /// Operating system release (e.g. `2.6.28`)
    pub fn sys_release() -> String {
        ffi::runtime_linux_Host::sys_release().to_string()
    }

    /// Operating system version
    pub fn sys_version() -> String {
        ffi::runtime_linux_Host::sys_version().to_string()
    }

    /// Hardware type identifier (e.g. `x86_64`)
    pub fn hardware() -> String {
        ffi::runtime_linux_Host::hardware().to_string()
    }
}
