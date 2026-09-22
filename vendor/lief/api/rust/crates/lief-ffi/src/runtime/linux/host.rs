#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/runtime/linux/Host.hpp");

        type runtime_linux_Host;

        #[Self = "runtime_linux_Host"]
        fn sys_name() -> UniquePtr<CxxString>;
        #[Self = "runtime_linux_Host"]
        fn sys_release() -> UniquePtr<CxxString>;
        #[Self = "runtime_linux_Host"]
        fn sys_version() -> UniquePtr<CxxString>;
        #[Self = "runtime_linux_Host"]
        fn hardware() -> UniquePtr<CxxString>;
    }
}
