#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/runtime/windows/LdrDataTableEntry.hpp");

        type runtime_windows_LdrDataTableEntry;
        type runtime_windows_it_ldr_data_table_entry;

        fn dll_base(self: &runtime_windows_LdrDataTableEntry) -> u64;
        fn entry_point(self: &runtime_windows_LdrDataTableEntry) -> u64;
        fn size_of_image(self: &runtime_windows_LdrDataTableEntry) -> u32;
        fn full_dll_name(self: &runtime_windows_LdrDataTableEntry) -> UniquePtr<CxxString>;
        fn base_dll_name(self: &runtime_windows_LdrDataTableEntry) -> UniquePtr<CxxString>;

        fn flags(self: &runtime_windows_LdrDataTableEntry) -> u32;
        fn obsolete_load_count(self: &runtime_windows_LdrDataTableEntry) -> u16;
        fn tls_index(self: &runtime_windows_LdrDataTableEntry) -> u16;
        fn time_date_stamp(self: &runtime_windows_LdrDataTableEntry) -> u32;
        fn entry_point_activation_context(self: &runtime_windows_LdrDataTableEntry) -> u64;
        fn lock(self: &runtime_windows_LdrDataTableEntry) -> u64;

        fn ddag_node(self: &runtime_windows_LdrDataTableEntry, is_set: Pin<&mut u32>) -> u64;
        fn load_context(self: &runtime_windows_LdrDataTableEntry, is_set: Pin<&mut u32>) -> u64;
        fn parent_dll_base(self: &runtime_windows_LdrDataTableEntry, is_set: Pin<&mut u32>) -> u64;
        fn switch_back_context(
            self: &runtime_windows_LdrDataTableEntry,
            is_set: Pin<&mut u32>,
        ) -> u64;
        fn original_base(self: &runtime_windows_LdrDataTableEntry, is_set: Pin<&mut u32>) -> u64;
        fn load_time(self: &runtime_windows_LdrDataTableEntry, is_set: Pin<&mut u32>) -> i64;
        fn base_name_hash_value(
            self: &runtime_windows_LdrDataTableEntry,
            is_set: Pin<&mut u32>,
        ) -> u32;
        fn load_reason(self: &runtime_windows_LdrDataTableEntry, is_set: Pin<&mut u32>) -> i32;
        fn implicit_path_options(
            self: &runtime_windows_LdrDataTableEntry,
            is_set: Pin<&mut u32>,
        ) -> u32;
        fn reference_count(self: &runtime_windows_LdrDataTableEntry, is_set: Pin<&mut u32>) -> u32;
        fn dependent_load_flags(
            self: &runtime_windows_LdrDataTableEntry,
            is_set: Pin<&mut u32>,
        ) -> u32;
        fn signing_level(self: &runtime_windows_LdrDataTableEntry, is_set: Pin<&mut u32>) -> u8;
        fn check_sum(self: &runtime_windows_LdrDataTableEntry, is_set: Pin<&mut u32>) -> u32;
        fn active_patch_image_base(
            self: &runtime_windows_LdrDataTableEntry,
            is_set: Pin<&mut u32>,
        ) -> u64;
        fn hot_patch_state(self: &runtime_windows_LdrDataTableEntry, is_set: Pin<&mut u32>) -> u32;

        fn to_string(self: &runtime_windows_LdrDataTableEntry) -> UniquePtr<CxxString>;

        fn next(
            self: Pin<&mut runtime_windows_it_ldr_data_table_entry>,
        ) -> UniquePtr<runtime_windows_LdrDataTableEntry>;
    }
    impl UniquePtr<runtime_windows_LdrDataTableEntry> {}
    impl UniquePtr<runtime_windows_it_ldr_data_table_entry> {}
}
