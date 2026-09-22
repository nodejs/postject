#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/runtime/linux/Module.hpp");

        type runtime_Module = crate::runtime::module::ffi::runtime_Module;
        type ELF_Binary = crate::elf::binary::ffi::ELF_Binary;
        type ELF_ParserConfig = crate::elf::binary::ffi::ELF_ParserConfig;

        type runtime_linux_Module;

        fn handle(self: &runtime_linux_Module) -> u64;
        fn dlsym(self: &runtime_linux_Module, name: &CxxString) -> u64;
        fn parse_from_path(self: &runtime_linux_Module) -> UniquePtr<ELF_Binary>;
        fn parse_from_path_with_config(
            self: &runtime_linux_Module,
            config: &ELF_ParserConfig,
        ) -> UniquePtr<ELF_Binary>;
        fn parse_from_memory(self: &runtime_linux_Module) -> UniquePtr<ELF_Binary>;
        fn parse_from_memory_with_config(
            self: &runtime_linux_Module,
            config: &ELF_ParserConfig,
        ) -> UniquePtr<ELF_Binary>;

        #[Self = "runtime_linux_Module"]
        fn from_handle(handle: u64) -> UniquePtr<runtime_linux_Module>;
        #[Self = "runtime_linux_Module"]
        fn classof(m: &runtime_Module) -> bool;

        fn runtime_linux_dlopen(name: &CxxString) -> UniquePtr<runtime_linux_Module>;
    }
    impl UniquePtr<runtime_linux_Module> {}
}
