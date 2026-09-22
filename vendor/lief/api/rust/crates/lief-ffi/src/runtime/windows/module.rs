#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/runtime/windows/Module.hpp");
        include!("LIEF/rust/COFF/Section.hpp");

        type runtime_Module = crate::runtime::module::ffi::runtime_Module;
        type PE_Binary = crate::pe::binary::ffi::PE_Binary;
        type PE_ParserConfig = crate::pe::binary::ffi::PE_ParserConfig;

        type runtime_windows_Module;

        fn handle(self: &runtime_windows_Module) -> u64;
        fn dlsym(self: &runtime_windows_Module, name: &CxxString) -> u64;
        fn parse_from_path(self: &runtime_windows_Module) -> UniquePtr<PE_Binary>;
        fn parse_from_path_with_config(
            self: &runtime_windows_Module,
            config: &PE_ParserConfig,
        ) -> UniquePtr<PE_Binary>;
        fn parse_from_memory(self: &runtime_windows_Module) -> UniquePtr<PE_Binary>;
        fn parse_from_memory_with_config(
            self: &runtime_windows_Module,
            config: &PE_ParserConfig,
        ) -> UniquePtr<PE_Binary>;

        #[Self = "runtime_windows_Module"]
        fn classof(m: &runtime_Module) -> bool;

        fn runtime_windows_find_module(name: &CxxString) -> UniquePtr<runtime_windows_Module>;
        fn runtime_windows_dlopen(name: &CxxString) -> UniquePtr<runtime_windows_Module>;
    }
    impl UniquePtr<runtime_windows_Module> {}
}
