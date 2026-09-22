#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/runtime/windows/PEB.hpp");

        type runtime_windows_PEB;
        type runtime_windows_it_ldr_data_table_entry =
            crate::runtime::windows::ldr_data_table_entry::ffi::runtime_windows_it_ldr_data_table_entry;

        fn being_debugged(self: &runtime_windows_PEB) -> bool;
        fn ldr(self: &runtime_windows_PEB) -> u64;
        fn process_parameters(self: &runtime_windows_PEB) -> u64;
        fn atl_thunk_slist_ptr(self: &runtime_windows_PEB) -> u64;
        fn atl_thunk_slist_ptr32(self: &runtime_windows_PEB) -> u32;
        fn post_process_init_routine(self: &runtime_windows_PEB) -> u64;
        fn session_id(self: &runtime_windows_PEB) -> u32;

        fn entries(
            self: &runtime_windows_PEB,
        ) -> UniquePtr<runtime_windows_it_ldr_data_table_entry>;
    }
    impl UniquePtr<runtime_windows_PEB> {}
}
