use std::ffi::c_void;

use lief_ffi as ffi;

use crate::common::{FromFFI, into_optional};
use crate::pe::{Binary, ParserConfig};
use crate::runtime;

/// This structure represents a Windows-specific module
pub struct Module {
    ptr: cxx::UniquePtr<ffi::runtime_windows_Module>,
}

impl FromFFI<ffi::runtime_windows_Module> for Module {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::runtime_windows_Module>) -> Self {
        Self { ptr }
    }
}

impl Module {
    /// Return the `HMODULE` handle as an opaque pointer.
    ///
    /// Return a nullptr if the function fails or if the handler can't be found
    pub fn handle(&self) -> *const c_void {
        self.ptr.handle() as *const c_void
    }

    /// Resolve the symbol with the given name for the current module
    pub fn dlsym(&self, name: String) -> *const c_void {
        cxx::let_cxx_string!(s = name);
        self.ptr.dlsym(&s) as *const c_void
    }

    /// Parse the PE module from its path on the filesystem
    pub fn parse_from_path(&self) -> Option<Binary> {
        into_optional(self.ptr.parse_from_path())
    }

    /// Parse the PE module from its path on the filesystem and given the parser
    /// configuration
    pub fn parse_from_path_with_config(&self, config: &ParserConfig) -> Option<Binary> {
        into_optional(self.ptr.parse_from_path_with_config(&config.to_ffi()))
    }

    /// Parse the PE module from memory
    pub fn parse_from_memory(&self) -> Option<Binary> {
        into_optional(self.ptr.parse_from_memory())
    }

    /// Parse the PE module from memory with the given configuration
    pub fn parse_from_memory_with_config(&self, config: &ParserConfig) -> Option<Binary> {
        into_optional(self.ptr.parse_from_memory_with_config(&config.to_ffi()))
    }
}

impl runtime::Module for Module {
    #[doc(hidden)]
    fn as_generic(&self) -> &ffi::runtime_Module {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

/// Load the module (DLL) with the given `name` into the current process and
/// wrap the resulting handle in a [`Module`].
///
/// ```rust,no_run
/// if let Some(kernel32) = lief::runtime::windows::dlopen("kernel32.dll") {
///     println!("{}", kernel32.path());
/// }
/// ```
///
/// This function relies on the Windows API `LoadLibrary`. To get a handle on a
/// module that is *already* loaded, prefer [`find_module`].
pub fn dlopen(name: &str) -> Option<Module> {
    cxx::let_cxx_string!(s = name);
    into_optional(ffi::runtime_windows_dlopen(&s))
}

/// Try to get the [`Module`] with the given name.
///
/// ```rust,no_run
/// if let Some(ntdll) = lief::runtime::windows::find_module("ntdll.dll") {
///     println!("{}", ntdll.path());
/// }
/// ```
///
/// This function relies on the Windows API `GetModuleHandle` which is more
/// efficient than the generic implementation
/// [`crate::runtime::module_from_name`].
pub fn find_module(name: &str) -> Option<Module> {
    cxx::let_cxx_string!(s = name);
    into_optional(ffi::runtime_windows_find_module(&s))
}
