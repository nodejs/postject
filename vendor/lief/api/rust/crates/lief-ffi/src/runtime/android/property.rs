#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/runtime/android/Property.hpp");

        type runtime_android_Property;
        type runtime_android_it_properties;

        fn name(self: &runtime_android_Property) -> UniquePtr<CxxString>;
        fn value(self: &runtime_android_Property) -> UniquePtr<CxxString>;
        fn serial(self: &runtime_android_Property) -> u32;
        fn to_string(self: &runtime_android_Property) -> UniquePtr<CxxString>;

        fn next(
            self: Pin<&mut runtime_android_it_properties>,
        ) -> UniquePtr<runtime_android_Property>;
    }
    impl UniquePtr<runtime_android_Property> {}
    impl UniquePtr<runtime_android_it_properties> {}
}
