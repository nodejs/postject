#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/runtime/osx/Host.hpp");

        type runtime_osx_Host;
        type runtime_osx_Host_version_t;

        #[Self = "runtime_osx_Host"]
        fn os_version_name() -> UniquePtr<CxxString>;

        #[Self = "runtime_osx_Host"]
        fn is_sip_enabled() -> bool;

        fn get_major(self: &runtime_osx_Host_version_t) -> u32;
        fn get_minor(self: &runtime_osx_Host_version_t) -> u32;
        fn get_patch(self: &runtime_osx_Host_version_t) -> u32;
        fn to_string(self: &runtime_osx_Host_version_t) -> UniquePtr<CxxString>;

        #[Self = "runtime_osx_Host_version_t"]
        fn os_version() -> UniquePtr<runtime_osx_Host_version_t>;
        #[Self = "runtime_osx_Host_version_t"]
        fn big_sur() -> UniquePtr<runtime_osx_Host_version_t>;
        #[Self = "runtime_osx_Host_version_t"]
        fn monterey() -> UniquePtr<runtime_osx_Host_version_t>;
        #[Self = "runtime_osx_Host_version_t"]
        fn ventura() -> UniquePtr<runtime_osx_Host_version_t>;
        #[Self = "runtime_osx_Host_version_t"]
        fn sonoma() -> UniquePtr<runtime_osx_Host_version_t>;
        #[Self = "runtime_osx_Host_version_t"]
        fn sequoia() -> UniquePtr<runtime_osx_Host_version_t>;
        #[Self = "runtime_osx_Host_version_t"]
        fn tahoe() -> UniquePtr<runtime_osx_Host_version_t>;
    }
    impl UniquePtr<runtime_osx_Host_version_t> {}
}
