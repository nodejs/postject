#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/runtime/osx/Module.hpp");

        type runtime_Module = crate::runtime::module::ffi::runtime_Module;
        type MachO_Binary = crate::macho::binary::ffi::MachO_Binary;

        type runtime_osx_Module;

        fn handle(self: &runtime_osx_Module) -> u64;
        fn dlsym(self: &runtime_osx_Module, name: &CxxString) -> u64;
        fn parse_from_path(self: &runtime_osx_Module) -> UniquePtr<MachO_Binary>;
        fn parse_from_memory(self: &runtime_osx_Module) -> UniquePtr<MachO_Binary>;

        #[Self = "runtime_osx_Module"]
        fn from_handle(handle: u64) -> UniquePtr<runtime_osx_Module>;
        #[Self = "runtime_osx_Module"]
        fn classof(m: &runtime_Module) -> bool;

        fn runtime_osx_dlopen(name: &CxxString) -> UniquePtr<runtime_osx_Module>;
    }
    impl UniquePtr<runtime_osx_Module> {}
}
