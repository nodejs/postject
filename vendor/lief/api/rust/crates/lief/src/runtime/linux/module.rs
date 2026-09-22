use std::ffi::c_void;

use lief_ffi as ffi;

use crate::common::{FromFFI, into_optional};
use crate::elf::{Binary, ParserConfig};
use crate::runtime;

/// This structure represents a Linux-specific module
pub struct Module {
    ptr: cxx::UniquePtr<ffi::runtime_linux_Module>,
}

impl FromFFI<ffi::runtime_linux_Module> for Module {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::runtime_linux_Module>) -> Self {
        Self { ptr }
    }
}

impl Module {
    /// Instantiate a [`Module`] from the given ``dlopen`` handle.
    pub fn from_handle(handle: *const c_void) -> Option<Module> {
        into_optional(ffi::runtime_linux_Module::from_handle(handle as u64))
    }

    /// Return the ``dlopen`` handle for this library as an opaque pointer.
    ///
    /// Return a null pointer if the function fails or if the handler can't be
    /// found.
    pub fn handle(&self) -> *const c_void {
        self.ptr.handle() as *const c_void
    }

    /// Resolve the symbol with the given name for the current module
    pub fn dlsym(&self, name: String) -> *const c_void {
        cxx::let_cxx_string!(s = name);
        self.ptr.dlsym(&s) as *const c_void
    }

    /// Parse the ELF module from its path on the filesystem
    pub fn parse_from_path(&self) -> Option<Binary> {
        into_optional(self.ptr.parse_from_path())
    }

    /// Parse the ELF module from its path on the filesystem and given the
    /// parser configuration
    pub fn parse_from_path_with_config(&self, config: &ParserConfig) -> Option<Binary> {
        into_optional(self.ptr.parse_from_path_with_config(&config.to_ffi()))
    }

    /// Parse the ELF module from memory
    pub fn parse_from_memory(&self) -> Option<Binary> {
        into_optional(self.ptr.parse_from_memory())
    }

    /// Parse the ELF module from memory with the given configuration
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

/// Load the library with the given path or name
pub fn dlopen(name: &str) -> Option<Module> {
    cxx::let_cxx_string!(s = name);
    into_optional(ffi::runtime_linux_dlopen(&s))
}
