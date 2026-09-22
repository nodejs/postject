#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/runtime/windows/Process.hpp");

        type runtime_windows_PEB = crate::runtime::windows::peb::ffi::runtime_windows_PEB;

        type runtime_windows_Process;

        #[Self = "runtime_windows_Process"]
        fn peb() -> UniquePtr<runtime_windows_PEB>;
    }
}
