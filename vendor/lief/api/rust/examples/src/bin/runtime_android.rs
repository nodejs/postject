use std::process::ExitCode;
use std::sync::Arc;

use lief::assembly::AssemblerConfig;
use lief::generic::Symbol;
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

    // lief-doc: host-android-start
    if let Some(sdk) = runtime::android::Host::sdk_version() {
        println!("    SDK:      {}", sdk);
    }
    // lief-doc: host-android-end
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

    // lief-doc: process-android-start
    // Query a single system property by name
    if let Some(prop) = runtime::android::Process::get_system_property("ro.build.version.sdk") {
        println!(
            "    {}: {} (serial: {})",
            prop.name(),
            prop.value(),
            prop.serial()
        );
    }

    // Iterate over all properties
    for prop in runtime::android::Process::properties() {
        println!(
            "    {}: {} (serial: {})",
            prop.name(),
            prop.value(),
            prop.serial()
        );
    }
    // lief-doc: process-android-end
}

fn modules_info() {
    println!("Module API");
    let mut libc: Option<runtime::android::Module> = None;
    // lief-doc: modules-start
    for module in runtime::modules() {
        println!(
            "{} ({:#010x} - {:#010x})",
            module.name(),
            module.imagebase(),
            module.end()
        );
        if let runtime::Modules::Android(android_mod) = module {
            if android_mod.name().ends_with("libc.so") {
                println!(
                    "libc.so found: {} ([{:#010x}, {:#010x}])",
                    android_mod.path(),
                    android_mod.imagebase(),
                    android_mod.end()
                );
                libc = Some(android_mod);
            }
        }
    }
    // lief-doc: modules-end

    let libc = match libc {
        Some(lib) => lib,
        None => return,
    };

    // lief-doc: modules-android-start
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

    if let Some(liblog) = runtime::android::dlopen("liblog.so") {
        println!(
            "liblog loaded: {} (dlopen handle={:#010x})",
            liblog.path(),
            liblog.handle() as usize
        );

        let log_print = liblog.dlsym("__android_log_print".to_string());
        if !log_print.is_null() {
            println!(
                "{}!__android_log_print: {:#010x}",
                liblog.name(),
                log_print as usize
            );
        }
    }
    // lief-doc: modules-android-end
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

    let mut config = AssemblerConfig::default();
    config.symbol_resolver = Some(Arc::new(|name: &str| -> Option<u64> {
        let libc = match runtime::android::dlopen("libc.so") {
            Some(lib) => lib,
            None => {
                eprintln!("Failed to dlopen libc.so");
                return None;
            }
        };

        if name == "write" {
            return Some(libc.dlsym("write".to_string()) as usize as u64);
        }
        None
    }));

    let raw_inst = runtime::assemble_with_config(
        chunk.addr(),
        r#"
        .text
            .global main
            .align 2

        main:
            stp     x29, x30, [sp, -16]!
            mov     x29, sp

            ldr     x8, =write

            mov     x0, 1    // STDOUT_FILENO
            adr     x1, msg  // buf = &msg
            mov     x2, 27   // len("LIEF Runtime Extended Demo\n")
            blr     x8       // write(STDOUT_FILENO, msg, 27)

            ldp     x29, x30, [sp], 16
            ret

        msg:
            .ascii "LIEF Runtime Extended Demo\n"
        "#,
        &config,
    );

    // Disassemble the JITed stub from memory
    for inst in runtime::disassemble(chunk.addr()).take(9) {
        println!("{}", inst);
    }

    // Dump the JITed stub as raw bytes
    let hex_bytes: Vec<String> = raw_inst.iter().map(|&b| format!("{:02x}", b)).collect();
    println!("{}", hex_bytes.join(":"));

    // Flush the instruction cache before executing the freshly written code
    // (this is required on AArch64).
    chunk.cache_flush();

    // Change the permission to R-X and invoke the JITed function
    chunk.make_rx();

    let hello_jit: unsafe extern "C" fn() = unsafe { std::mem::transmute(chunk.addr() as usize) };
    unsafe { hello_jit() };

    // Change the message: locate it in the generated bytes and rewrite it.
    let needle = b"LIEF Runtime";
    if let Some(msg_off) = raw_inst.windows(needle.len()).position(|w| w == needle) {
        let new_msg = b"Hello Rust runtime World!\n";
        chunk.make_rw();
        unsafe {
            let dst = (chunk.addr() as usize + msg_off) as *mut u8;
            std::ptr::copy_nonoverlapping(new_msg.as_ptr(), dst, new_msg.len());
        }
        chunk.make_rx();
        chunk.cache_flush();
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
