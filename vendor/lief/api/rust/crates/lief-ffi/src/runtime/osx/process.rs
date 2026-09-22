#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/runtime/osx/Process.hpp");

        type runtime_osx_Process;

        #[Self = "runtime_osx_Process"]
        fn dyld_version() -> UniquePtr<CxxString>;
    }
}
