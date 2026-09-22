use lief_ffi as ffi;

use crate::common::FromFFI;
use crate::declare_standalone_fwd_iterator;
use crate::to_opt;

/// This structure exposes a user-friendly interface over a `LDR_DATA_TABLE_ENTRY`,
/// the structure used by the Windows loader to describe a module loaded in the
/// current process.
///
/// These entries can be enumerated through [`super::PEB::entries`].
pub struct LdrDataTableEntry {
    ptr: cxx::UniquePtr<ffi::runtime_windows_LdrDataTableEntry>,
}

impl FromFFI<ffi::runtime_windows_LdrDataTableEntry> for LdrDataTableEntry {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::runtime_windows_LdrDataTableEntry>) -> Self {
        Self { ptr }
    }
}

impl LdrDataTableEntry {
    /// Base address at which the module is mapped in memory (`DllBase`).
    pub fn dll_base(&self) -> u64 {
        self.ptr.dll_base()
    }

    /// Address of the entry point of the module (`EntryPoint`).
    pub fn entry_point(&self) -> u64 {
        self.ptr.entry_point()
    }

    /// Size (in bytes) of the module's image in memory (`SizeOfImage`).
    pub fn size_of_image(&self) -> u32 {
        self.ptr.size_of_image()
    }

    /// Full path of the module (`FullDllName`),
    /// e.g. `C:\Windows\System32\ntdll.dll`.
    pub fn full_dll_name(&self) -> String {
        self.ptr.full_dll_name().to_string()
    }

    /// Base name of the module (`BaseDllName`), e.g. `ntdll.dll`.
    pub fn base_dll_name(&self) -> String {
        self.ptr.base_dll_name().to_string()
    }

    /// Loader flags describing the state of the module (`Flags`).
    pub fn flags(&self) -> u32 {
        self.ptr.flags()
    }

    /// Legacy load count of the module (`ObsoleteLoadCount`). Superseded by
    /// [`LdrDataTableEntry::reference_count`] on Windows 8 and later.
    pub fn obsolete_load_count(&self) -> u16 {
        self.ptr.obsolete_load_count()
    }

    /// TLS slot index assigned to the module, or `0` when it has no TLS
    /// (`TlsIndex`).
    pub fn tls_index(&self) -> u16 {
        self.ptr.tls_index()
    }

    /// `TimeDateStamp` of the module as cached by the loader.
    pub fn time_date_stamp(&self) -> u32 {
        self.ptr.time_date_stamp()
    }

    /// Address of the activation context associated with the module's entry
    /// point.
    pub fn entry_point_activation_context(&self) -> u64 {
        self.ptr.entry_point_activation_context()
    }

    /// Address of the per-entry loader lock.
    pub fn lock(&self) -> u64 {
        self.ptr.lock()
    }

    /// Address of the dependency-graph node of the module (`DdagNode`).
    ///
    /// Available on Windows 8 and later.
    pub fn ddag_node(&self) -> Option<u64> {
        to_opt!(&ffi::runtime_windows_LdrDataTableEntry::ddag_node, &self);
    }

    /// Address of the loader context used while the module is being snapped
    ///
    /// Available on Windows 8 and later.
    pub fn load_context(&self) -> Option<u64> {
        to_opt!(&ffi::runtime_windows_LdrDataTableEntry::load_context, &self);
    }

    /// Base address of the module that triggered the load of this one.
    ///
    /// Available on Windows 8 and later.
    pub fn parent_dll_base(&self) -> Option<u64> {
        to_opt!(
            &ffi::runtime_windows_LdrDataTableEntry::parent_dll_base,
            &self
        );
    }

    /// Address of the CHPE switch-back context.
    ///
    /// Available on Windows 8 and later.
    pub fn switch_back_context(&self) -> Option<u64> {
        to_opt!(
            &ffi::runtime_windows_LdrDataTableEntry::switch_back_context,
            &self
        );
    }

    /// Preferred base address recorded in the PE headers
    ///
    /// Available on Windows 8 and later.
    pub fn original_base(&self) -> Option<u64> {
        to_opt!(
            &ffi::runtime_windows_LdrDataTableEntry::original_base,
            &self
        );
    }

    /// Time at which the module was loaded.
    ///
    /// Available on Windows 8 and later.
    pub fn load_time(&self) -> Option<i64> {
        to_opt!(&ffi::runtime_windows_LdrDataTableEntry::load_time, &self);
    }

    /// Hash of the module's base name used to index the loader tables
    ///
    /// Available on Windows 8 and later.
    pub fn base_name_hash_value(&self) -> Option<u32> {
        to_opt!(
            &ffi::runtime_windows_LdrDataTableEntry::base_name_hash_value,
            &self
        );
    }

    /// Reason why the module was loaded, as a `LDR_DLL_LOAD_REASON` value
    ///
    /// Available on Windows 8 and later.
    pub fn load_reason(&self) -> Option<i32> {
        to_opt!(&ffi::runtime_windows_LdrDataTableEntry::load_reason, &self);
    }

    /// Path-search options implied when the module was resolved
    ///
    /// Available on Windows 8 and later.
    pub fn implicit_path_options(&self) -> Option<u32> {
        to_opt!(
            &ffi::runtime_windows_LdrDataTableEntry::implicit_path_options,
            &self
        );
    }

    /// Number of references currently held on the module.
    ///
    /// Available on Windows 8 and later.
    pub fn reference_count(&self) -> Option<u32> {
        to_opt!(
            &ffi::runtime_windows_LdrDataTableEntry::reference_count,
            &self
        );
    }

    /// Flags controlling how the statically-linked dependencies of the module
    /// are loaded.
    ///
    /// Available on Windows 8 and later.
    pub fn dependent_load_flags(&self) -> Option<u32> {
        to_opt!(
            &ffi::runtime_windows_LdrDataTableEntry::dependent_load_flags,
            &self
        );
    }

    /// Signing level of the module's image, as a `SE_SIGNING_LEVEL` value
    ///
    /// Available on Windows 10 and later.
    pub fn signing_level(&self) -> Option<u8> {
        to_opt!(
            &ffi::runtime_windows_LdrDataTableEntry::signing_level,
            &self
        );
    }

    /// Image checksum cached by the loader
    ///
    /// Available on Windows 10 and later.
    pub fn check_sum(&self) -> Option<u32> {
        to_opt!(&ffi::runtime_windows_LdrDataTableEntry::check_sum, &self);
    }

    /// Base address of the active hot-patch image, if any.
    ///
    /// Available on Windows 11 and later.
    pub fn active_patch_image_base(&self) -> Option<u64> {
        to_opt!(
            &ffi::runtime_windows_LdrDataTableEntry::active_patch_image_base,
            &self
        );
    }

    /// State of the hot-patch engine for this module, as a
    /// `LDR_HOT_PATCH_STATE` value.
    ///
    /// Available on Windows 11 and later.
    pub fn hot_patch_state(&self) -> Option<u32> {
        to_opt!(
            &ffi::runtime_windows_LdrDataTableEntry::hot_patch_state,
            &self
        );
    }
}

impl std::fmt::Display for LdrDataTableEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.ptr.to_string())
    }
}

declare_standalone_fwd_iterator!(
    LdrDataTableEntries,
    LdrDataTableEntry,
    ffi::runtime_windows_LdrDataTableEntry,
    ffi::runtime_windows_it_ldr_data_table_entry
);
