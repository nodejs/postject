use lief_ffi as ffi;

use super::ldr_data_table_entry::LdrDataTableEntries;
use crate::common::FromFFI;

/// This structure exposes a user-friendly interface over the Process
/// Environment Block (PEB) of the current process.
///
/// It can be accessed through [`super::Process::peb`].
pub struct PEB {
    ptr: cxx::UniquePtr<ffi::runtime_windows_PEB>,
}

impl FromFFI<ffi::runtime_windows_PEB> for PEB {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::runtime_windows_PEB>) -> Self {
        Self { ptr }
    }
}

impl PEB {
    /// Whether the current process is being debugged.
    ///
    /// This mirrors the `BeingDebugged` field of the PEB and is equivalent to
    /// the result of the `IsDebuggerPresent()` API.
    pub fn being_debugged(&self) -> bool {
        self.ptr.being_debugged()
    }

    /// Address of the loader data structure (`PEB_LDR_DATA`) which holds the
    /// list of the modules loaded in the current process.
    pub fn ldr(&self) -> u64 {
        self.ptr.ldr()
    }

    /// Address of the process parameters (`RTL_USER_PROCESS_PARAMETERS`) which
    /// holds information such as the command line or the current directory.
    pub fn process_parameters(&self) -> u64 {
        self.ptr.process_parameters()
    }

    /// Address of the per-process ATL thunk SList (single-linked list).
    pub fn atl_thunk_slist_ptr(&self) -> u64 {
        self.ptr.atl_thunk_slist_ptr()
    }

    /// 32-bit value of the ATL thunk SList pointer.
    pub fn atl_thunk_slist_ptr32(&self) -> u32 {
        self.ptr.atl_thunk_slist_ptr32()
    }

    /// Address of the routine called once the process completed its
    /// initialization (`PostProcessInitRoutine`).
    pub fn post_process_init_routine(&self) -> u64 {
        self.ptr.post_process_init_routine()
    }

    /// Session ID associated with the current process.
    pub fn session_id(&self) -> u32 {
        self.ptr.session_id()
    }

    /// Return a forward iterator over the modules referenced by the loader
    /// data (`Ldr`) of the PEB, in load order.
    pub fn entries(&self) -> LdrDataTableEntries {
        LdrDataTableEntries::new(self.ptr.entries())
    }
}
