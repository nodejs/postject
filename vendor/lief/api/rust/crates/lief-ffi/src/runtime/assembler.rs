#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/runtime/Assembler.hpp");

        type AssemblerConfig_r = crate::asm::config::AssemblerConfig_r;

        fn runtime_assemble(address: u64, Asm: &CxxString) -> UniquePtr<CxxVector<u8>>;
        fn runtime_assemble_with_config(
            address: u64,
            Asm: &CxxString,
            ffi_config: &AssemblerConfig_r,
        ) -> UniquePtr<CxxVector<u8>>;
    }
}
