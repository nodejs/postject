#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/runtime/android/Process.hpp");

        type runtime_android_Process;
        type runtime_android_Property =
            crate::runtime::android::property::ffi::runtime_android_Property;
        type runtime_android_it_properties =
            crate::runtime::android::property::ffi::runtime_android_it_properties;

        #[Self = "runtime_android_Process"]
        fn cmdline() -> UniquePtr<CxxString>;

        #[Self = "runtime_android_Process"]
        fn get_system_property(name: &CxxString) -> UniquePtr<runtime_android_Property>;

        #[Self = "runtime_android_Process"]
        fn properties() -> UniquePtr<runtime_android_it_properties>;
    }
}
