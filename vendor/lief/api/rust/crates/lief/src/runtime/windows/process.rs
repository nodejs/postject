use lief_ffi as ffi;

use super::PEB;
use crate::common::into_optional;

/// This structure exposes Windows-specific API for the current process.
pub struct Process {}

impl Process {
    /// Return an interface over the internal Process Environment Block (PEB)
    /// of the current process.
    pub fn peb() -> Option<PEB> {
        into_optional(ffi::runtime_windows_Process::peb())
    }
}
