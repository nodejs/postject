#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/runtime/Disassembler.hpp");

        type asm_Instruction = crate::asm::instruction::ffi::asm_Instruction;
        type runtime_it_instructions;

        fn next(self: Pin<&mut runtime_it_instructions>) -> UniquePtr<asm_Instruction>;

        fn runtime_disassemble(addr: u64) -> UniquePtr<runtime_it_instructions>;
    }
    impl UniquePtr<runtime_it_instructions> {}
}
