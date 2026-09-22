use lief_ffi as ffi;

use crate::assembly;
use crate::common::FromFFI;
use crate::declare_standalone_fwd_iterator;

/// Start disassembling instructions at the given **absolute** virtual address.
///
/// ```rust,no_run
/// use lief::runtime;
///
/// for inst in runtime::disassemble(0x7f0011223344) {
///     println!("{}", inst);
/// }
/// ```
pub fn disassemble(addr: u64) -> InstructionsIt {
    InstructionsIt::new(ffi::runtime_disassemble(addr))
}

declare_standalone_fwd_iterator!(
    InstructionsIt,
    assembly::Instructions,
    ffi::asm_Instruction,
    ffi::runtime_it_instructions
);
