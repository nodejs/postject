#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/ObjC/Category.hpp");

        type ObjC_DeclOpt = crate::objc::decl_opt::ffi::ObjC_DeclOpt;
        type ObjC_Method = crate::objc::method::ffi::ObjC_Method;
        type ObjC_Property = crate::objc::property::ffi::ObjC_Property;
        type ObjC_Protocol = crate::objc::protocol::ffi::ObjC_Protocol;

        type ObjC_Category;

        fn name(self: &ObjC_Category) -> UniquePtr<CxxString>;
        fn class_name(self: &ObjC_Category) -> UniquePtr<CxxString>;
        fn methods(self: &ObjC_Category) -> UniquePtr<ObjC_Category_it_methods>;
        fn protocols(self: &ObjC_Category) -> UniquePtr<ObjC_Category_it_protocols>;
        fn properties(self: &ObjC_Category) -> UniquePtr<ObjC_Category_it_properties>;
        fn to_decl(self: &ObjC_Category) -> UniquePtr<CxxString>;
        fn to_decl_with_opt(self: &ObjC_Category, opt: &ObjC_DeclOpt) -> UniquePtr<CxxString>;

        type ObjC_Category_it_methods;

        fn next(self: Pin<&mut ObjC_Category_it_methods>) -> UniquePtr<ObjC_Method>;
        fn size(self: &ObjC_Category_it_methods) -> u64;

        type ObjC_Category_it_protocols;

        fn next(self: Pin<&mut ObjC_Category_it_protocols>) -> UniquePtr<ObjC_Protocol>;
        fn size(self: &ObjC_Category_it_protocols) -> u64;

        type ObjC_Category_it_properties;

        fn next(self: Pin<&mut ObjC_Category_it_properties>) -> UniquePtr<ObjC_Property>;
        fn size(self: &ObjC_Category_it_properties) -> u64;
    }

    impl UniquePtr<ObjC_Category> {}
    impl UniquePtr<ObjC_Category_it_methods> {}
    impl UniquePtr<ObjC_Category_it_protocols> {}
    impl UniquePtr<ObjC_Category_it_properties> {}
}
