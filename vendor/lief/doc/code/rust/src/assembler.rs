use std::collections::HashMap;
use std::sync::Arc;

use lief::assembly::Instruction;
use lief::generic::{Binary, Symbol};

pub fn disassemble_assemble(some_elf: &mut lief::elf::Binary) {
    // lief-doc: disassemble-assemble-start
    let elf: &mut lief::elf::Binary = some_elf;

    let syscall_addresses: Vec<u64> = elf
        .disassemble_address(0x400090)
        .filter(|inst| inst.is_syscall())
        .map(|inst| inst.address())
        .collect();

    for addr in syscall_addresses {
        elf.assemble(
            addr,
            r#"
            mov x1, x0;
            str x1, [x2, #8];
            "#,
        );
    }
    // lief-doc: disassemble-assemble-end
}

pub fn context_error(some_elf: &mut lief::elf::Binary) {
    // lief-doc: context-error-start
    let elf: &mut lief::elf::Binary = some_elf;

    elf.assemble(
        elf.entrypoint(),
        r#"
        mov rdi, rax;
        call a_custom_function;
        "#,
    );
    // lief-doc: context-error-end
}

pub fn config_resolver(some_elf: &mut lief::elf::Binary) {
    // lief-doc: config-resolver-start
    let elf: &mut lief::elf::Binary = some_elf;

    let mut config = lief::assembly::AssemblerConfig::default();

    let resolver = Arc::new(|symbol: &str| {
        if symbol == "a_custom_function" {
            return Some(0x1000);
        }
        None
    });

    config.symbol_resolver = Some(resolver);

    elf.assemble_with_config(
        elf.entrypoint(),
        r#"
        mov rdi, rax;
        call a_custom_function;
        "#,
        &config,
    );
    // lief-doc: config-resolver-end
}

pub fn config_target(some_elf: &mut lief::elf::Binary) {
    // lief-doc: config-target-start
    let elf: &mut lief::elf::Binary = some_elf;

    let mut config = lief::assembly::AssemblerConfig::default();

    let sym_map: HashMap<String, u64> = elf
        .exported_symbols()
        .map(|sym| (sym.name(), sym.value()))
        .collect();

    let resolver = Arc::new(move |symbol: &str| sym_map.get(symbol).copied());

    config.symbol_resolver = Some(resolver);

    elf.assemble_with_config(
        elf.entrypoint(),
        r#"
        mov rdi, rax;
        call a_custom_function;
        "#,
        &config,
    );
    // lief-doc: config-target-end
}

pub fn disable_instruction(some_elf: &mut lief::elf::Binary) {
    // lief-doc: nop-out-start
    let elf: &mut lief::elf::Binary = some_elf;

    // Overwrite the first call in the region (e.g. a call to an anti-debugging
    // routine) with nops
    let target = elf
        .disassemble_address(0x401200)
        .find(|inst| inst.is_call())
        .map(|inst| (inst.address(), inst.size()));

    if let Some((address, size)) = target {
        elf.assemble(address, &"nop\n".repeat(size as usize));
    }

    elf.write("patched.bin");
    // lief-doc: nop-out-end
}
