#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/runtime/Host.hpp");

        type runtime_Host;

        #[Self = "runtime_Host"]
        fn name() -> UniquePtr<CxxString>;
        #[Self = "runtime_Host"]
        fn home_dir() -> UniquePtr<CxxString>;
        #[Self = "runtime_Host"]
        fn tmp_dir() -> UniquePtr<CxxString>;
        #[Self = "runtime_Host"]
        fn config_dir() -> UniquePtr<CxxString>;
        #[Self = "runtime_Host"]
        fn cache_dir() -> UniquePtr<CxxString>;
    }
}
