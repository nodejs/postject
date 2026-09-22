use std::process::ExitCode;

use lief::generic::{Relocation, Symbol};
use lief::runtime;
use lief::runtime::memory::{MmapFlags, Perm};
use lief::runtime::module::Module;

fn host_info() {
    println!("Host");
    // lief-doc: host-start
    println!("    Hostname: {}", runtime::Host::name());
    println!("    Home:     {}", runtime::Host::home_dir());
    println!("    Cache:    {}", runtime::Host::cache_dir());
    println!("    Temp:     {}", runtime::Host::tmp_dir());
    println!("    Config:   {}", runtime::Host::config_dir());
    // lief-doc: host-end

    // lief-doc: host-linux-start
    println!("    sys_name:    {}", runtime::linux::Host::sys_name());
    println!("    sys_release: {}", runtime::linux::Host::sys_release());
    println!("    sys_version: {}", runtime::linux::Host::sys_version());
    println!("    hardware:    {}", runtime::linux::Host::hardware());
    // lief-doc: host-linux-end
}

fn process_info() {
    println!("Process");
    // lief-doc: process-start
    println!("    PID:       {}", runtime::Process::pid());
    println!("    TID:       {}", runtime::Process::tid());
    println!("    Page size: {:#06x}", runtime::Process::page_size());
    println!("    Arch:      {:?}", runtime::Process::arch());
    println!("    Platform:  {:?}", runtime::Process::platform());
    // lief-doc: process-end

    // lief-doc: process-linux-start
    if let Some(version) = runtime::linux::Process::glibc_version() {
        println!("    glibc:    {}", version);
    }
    // lief-doc: process-linux-end
}

fn modules_info() {
    println!("Module API");
    let mut libc: Option<runtime::linux::Module> = None;
    // lief-doc: modules-start
    for module in runtime::modules() {
        println!(
            "{} ({:#010x} - {:#010x})",
            module.name(),
            module.imagebase(),
            module.end()
        );
        if let runtime::Modules::Linux(linux_mod) = module {
            if linux_mod.name().starts_with("libc.so") {
                println!(
                    "libc.so found: {} ([{:#010x}, {:#010x}])",
                    linux_mod.path(),
                    linux_mod.imagebase(),
                    linux_mod.end()
                );
                libc = Some(linux_mod);
            }
        }
    }
    // lief-doc: modules-end

    let libc = match libc {
        Some(lib) => lib,
        None => return,
    };

    // lief-doc: modules-linux-start
    println!("libc path: {}", libc.path());
    let cxa_finalize = libc.dlsym("__cxa_finalize".to_string());
    if !cxa_finalize.is_null() {
        println!(
            "{}!__cxa_finalize: {:#010x}",
            libc.name(),
            cxa_finalize as usize
        );
    }

    let malloc = libc.dlsym("malloc".to_string());
    if !malloc.is_null() {
        println!("{}!malloc: {:#010x}", libc.name(), malloc as usize);
    }

    // Parse the ELF from its path on the disk
    if let Some(elf_on_disk) = libc.parse_from_path() {
        for sym in elf_on_disk.dynamic_symbols() {
            if sym.name() == "__cxa_finalize" {
                println!("__cxa_finalize: {:#010x}", sym.value());
                break;
            }
        }
    }

    // Load 'librt.so' and wrap the dlopen handle in a Module.
    if let Some(librt) = runtime::linux::dlopen("librt.so.1") {
        println!(
            "librt loaded: {} (dlopen handle={:#010x})",
            librt.path(),
            librt.handle() as usize
        );

        // Parse the ELF directly from memory.
        if let Some(librt_mem) = librt.parse_from_memory() {
            // Find the relocation for the imported symbol `__cxa_finalize`
            // defined in libc. Reading the relocation address returns the
            // resolved address, which should match what dlsym returned.
            for reloc in librt_mem.relocations() {
                let sym = match reloc.symbol() {
                    Some(s) => s,
                    None => continue,
                };
                if sym.name() != "__cxa_finalize" {
                    continue;
                }
                let abs_reloc_addr = librt.imagebase() + reloc.address();
                // Assume a 64-bit architecture
                let resolved: u64 = unsafe { runtime::Memory::read(abs_reloc_addr) };
                println!(
                    "{} -> {:#010x} -> {:#010x}",
                    librt.name(),
                    abs_reloc_addr,
                    resolved
                );
                break;
            }
        }
    }
    // lief-doc: modules-linux-end
}

fn memory_example() {
    println!("Memory");
    // lief-doc: memory-start
    let mut chunk = match runtime::Memory::mmap(
        runtime::Process::page_size() as u64,
        MmapFlags::ANONYMOUS | MmapFlags::PRIVATE,
        Perm::READ | Perm::WRITE | Perm::EXEC,
    ) {
        Some(c) => c,
        None => return,
    };

    let raw_inst = runtime::assemble(
        chunk.addr(),
        r#"
        .global _start

        .text
        _start:
            push 1
            pop  rax
            mov  edi, eax
            lea  rsi, [rip + msg]
            mov  rdx, 28
            syscall
            ret

        msg:
            .ascii "LIEF Runtime Extended Demo\n"
        "#,
    );

    // Dump the generated instruction bytes
    println!(
        "{} bytes assembled at {:#010x}",
        raw_inst.len(),
        chunk.addr()
    );

    // Change the permission to R-X and invoke the JITed function
    chunk.make_rx();

    let hello_jit: unsafe extern "C" fn() = unsafe { std::mem::transmute(chunk.addr() as usize) };
    unsafe { hello_jit() };

    // Locate the message in the generated bytes and rewrite it.
    let needle = b"LIEF Runtime";
    if let Some(msg_off) = raw_inst.windows(needle.len()).position(|w| w == needle) {
        let new_msg = b"Hello Rust runtime World!\n\0";
        chunk.make_rw();
        unsafe {
            let dst = (chunk.addr() as usize + msg_off) as *mut u8;
            std::ptr::copy_nonoverlapping(new_msg.as_ptr(), dst, new_msg.len() - 1);
        }
        chunk.make_rx();
        unsafe { hello_jit() };
    }

    // Don't miss good practices!
    let _ = chunk.deallocate();
    // lief-doc: memory-end
}

fn main() -> ExitCode {
    if !runtime::enabled() {
        eprintln!("Error: LIEF's runtime is not enabled");
        return ExitCode::SUCCESS;
    }

    host_info();
    process_info();
    modules_info();
    memory_example();
    ExitCode::SUCCESS
}
