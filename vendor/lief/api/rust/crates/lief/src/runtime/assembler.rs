use lief_ffi as ffi;

use crate::assembly::AssemblerConfig;

/// Assemble the provided assembly code at the specified (absolute) virtual
/// address.
///
/// The generated assembly bytes are returned by the function.
///
/// ```rust,no_run
/// use lief::runtime;
///
/// let code = runtime::assemble(0x7f0011223344, r#"
///     xor rax, rbx;
///     mov rcx, rax;
/// "#);
/// ```
pub fn assemble(address: u64, asm: &str) -> Vec<u8> {
    cxx::let_cxx_string!(__cxx_s = asm);
    Vec::from(ffi::runtime_assemble(address, &__cxx_s).as_slice())
}

/// Same as [`assemble`] but this function takes an extra [`AssemblerConfig`]
/// that is used to configure the assembly engine: dialect, symbols definitions.
pub fn assemble_with_config(address: u64, asm: &str, config: &AssemblerConfig) -> Vec<u8> {
    let ffi_config = config.into_ffi();
    cxx::let_cxx_string!(__cxx_s = asm);
    Vec::from(ffi::runtime_assemble_with_config(address, &__cxx_s, ffi_config.as_ref()).as_slice())
}
