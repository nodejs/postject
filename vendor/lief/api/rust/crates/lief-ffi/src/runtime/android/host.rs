#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/runtime/android/Host.hpp");

        type runtime_android_Host;

        #[Self = "runtime_android_Host"]
        fn sdk_version() -> i64;
    }
}
