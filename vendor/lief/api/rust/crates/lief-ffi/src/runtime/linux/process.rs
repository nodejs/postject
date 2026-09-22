#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/runtime/linux/Process.hpp");

        type runtime_linux_Process;

        #[Self = "runtime_linux_Process"]
        fn cmdline() -> UniquePtr<CxxString>;

        #[Self = "runtime_linux_Process"]
        fn glibc_version() -> UniquePtr<CxxString>;
    }
}
