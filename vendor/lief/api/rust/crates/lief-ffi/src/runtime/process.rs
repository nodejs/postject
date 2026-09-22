#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/runtime/Process.hpp");

        type runtime_Process;

        #[Self = "runtime_Process"]
        fn pid() -> i32;
        #[Self = "runtime_Process"]
        fn tid() -> i32;
        #[Self = "runtime_Process"]
        fn platform() -> u32;
        #[Self = "runtime_Process"]
        fn arch() -> u32;
        #[Self = "runtime_Process"]
        fn page_size() -> u32;
    }
}
