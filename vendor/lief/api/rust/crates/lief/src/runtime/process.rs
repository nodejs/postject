use super::{Arch, Platform};
use lief_ffi as ffi;

/// This structure represents the current process and provides functions to query process-level
/// information.
pub struct Process {}

impl Process {
    /// Get the Process ID of the current process.
    pub fn pid() -> i32 {
        ffi::runtime_Process::pid()
    }

    /// Get the Thread ID of the current thread.
    pub fn tid() -> i32 {
        ffi::runtime_Process::tid()
    }

    /// Return the number of bytes in a memory page.
    ///
    /// For instance:
    /// * `0x1000` (4096 bytes) for x86_64
    /// * `0x4000` (16384 bytes) for ARM64
    pub fn page_size() -> u32 {
        ffi::runtime_Process::page_size()
    }

    /// Target architecture of the current process
    pub fn arch() -> Arch {
        Arch::from(ffi::runtime_Process::arch())
    }

    /// Target platform of the current process
    pub fn platform() -> Platform {
        Platform::from(ffi::runtime_Process::platform())
    }

    /// Return the value of the environment variable `key` for the current
    /// process, or `None` if it is not set (or not valid Unicode).
    pub fn get_env(key: &str) -> Option<String> {
        std::env::var(key).ok()
    }

    /// Return all the environment variables of the current process as a
    /// `name -> value` map.
    pub fn get_envs() -> std::collections::HashMap<String, String> {
        std::env::vars_os()
            .filter_map(|(key, value)| Some((key.into_string().ok()?, value.into_string().ok()?)))
            .collect()
    }
}
