#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/runtime/windows/Host.hpp");

        type runtime_windows_Host;
        type runtime_windows_Host_version_t;

        fn get_major(self: &runtime_windows_Host_version_t) -> u32;
        fn get_minor(self: &runtime_windows_Host_version_t) -> u32;
        fn get_build_number(self: &runtime_windows_Host_version_t) -> u32;

        #[Self = "runtime_windows_Host"]
        fn version() -> UniquePtr<runtime_windows_Host_version_t>;
    }
    impl UniquePtr<runtime_windows_Host_version_t> {}
}
