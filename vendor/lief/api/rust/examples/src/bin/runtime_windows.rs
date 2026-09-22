use std::process::ExitCode;
use std::sync::Arc;

use lief::assembly::{AssemblerConfig, Instruction};
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

    // lief-doc: host-windows-start
    if let Some(version) = runtime::windows::Host::version() {
        println!("    Version:  {}", version);
    }
    // lief-doc: host-windows-end
}

fn process_info() {
    println!("Process");
    // lief-doc: process-start
    println!("    PID:       {}", runtime::Process::pid());
    println!("    TID:       {}", runtime::Process::tid());
    println!("    Page size: {:#06x}", runtime::Process::page_size());
    println!("    Arch:      {:?}", runtime::Process::arch());
    println!("    Platform:  {:?}", runtime::Process::platform());
    if let Some(userdomain) = runtime::Process::get_env("USERDOMAIN") {
        println!("    USERDOMAIN:{}", userdomain);
    }
    // lief-doc: process-end

    // lief-doc: process-windows-start
    if let Some(peb) = runtime::windows::Process::peb() {
        println!("    PEB.BeingDebugged:          {}", peb.being_debugged());
        println!("    PEB.Ldr:                    {:#06x}", peb.ldr());
        println!(
            "    PEB.ProcessParameters:      {:#06x}",
            peb.process_parameters()
        );
        println!(
            "    PEB.AtlThunkSListPtr:       {:#06x}",
            peb.atl_thunk_slist_ptr()
        );
        println!(
            "    PEB.AtlThunkSListPtr32:     {:#06x}",
            peb.atl_thunk_slist_ptr32()
        );
        println!(
            "    PEB.PostProcessInitRoutine: {:#06x}",
            peb.post_process_init_routine()
        );
        println!("    PEB.SessionId:              {:#06x}", peb.session_id());
    }
    // lief-doc: process-windows-end

    // lief-doc: peb-modules-start
    if let Some(peb) = runtime::windows::Process::peb() {
        let modules: Vec<_> = peb.entries().collect();
        for (i, entry) in modules.iter().take(3).enumerate() {
            println!(
                "    module[{}]: {} (base={:#06x}, size={:#06x})",
                i,
                entry.base_dll_name(),
                entry.dll_base(),
                entry.size_of_image()
            );
        }
        println!("    -> {} modules in the load order list", modules.len());
        if let Some(last) = modules.last() {
            println!("    last module: {}", last.base_dll_name());
        }
    }
    // lief-doc: peb-modules-end

    // lief-doc: peb-module-details-start
    if let Some(peb) = runtime::windows::Process::peb() {
        if let Some(first) = peb.entries().next() {
            println!(
                "    {} extended LDR_DATA_TABLE_ENTRY fields:",
                first.base_dll_name()
            );
            // Always available across the supported Windows versions:
            println!("      Flags:             {:#06x}", first.flags());
            println!("      ObsoleteLoadCount: {}", first.obsolete_load_count());
            println!("      TlsIndex:          {:#06x}", first.tls_index());
            println!("      TimeDateStamp:     {:#06x}", first.time_date_stamp());
            // Version-gated fields are None when the host kernel predates them:
            if let Some(v) = first.ddag_node() {
                println!("      DdagNode:          {:#06x}", v); // Windows 8+
            }
            if let Some(v) = first.original_base() {
                println!("      OriginalBase:      {:#06x}", v); // Windows 8+
            }
            if let Some(v) = first.load_reason() {
                println!("      LoadReason:        {}", v); // Windows 8+
            }
            if let Some(v) = first.signing_level() {
                println!("      SigningLevel:      {}", v); // Windows 10+
            }
            if let Some(v) = first.check_sum() {
                println!("      CheckSum:          {:#06x}", v); // Windows 10+
            }
            if let Some(v) = first.hot_patch_state() {
                println!("      HotPatchState:     {}", v); // Windows 11+
            }
        }
    }
    // lief-doc: peb-module-details-end
}

fn modules_info() {
    println!("Module API");
    let mut ntdll: Option<runtime::windows::Module> = None;
    // lief-doc: modules-start
    for module in runtime::modules() {
        println!(
            "{} ({:#010x} - {:#010x})",
            module.name(),
            module.imagebase(),
            module.end()
        );
        if let runtime::Modules::Windows(win_mod) = module {
            if win_mod.name().ends_with("ntdll.dll") {
                println!(
                    "ntdll.dll found: {} ([{:#010x}, {:#010x}])",
                    win_mod.path(),
                    win_mod.imagebase(),
                    win_mod.end()
                );
                ntdll = Some(win_mod);
            }
        }
    }
    // lief-doc: modules-end

    let ntdll = match ntdll {
        Some(m) => m,
        None => return,
    };

    // lief-doc: modules-windows-start
    println!("ntdll path: {}", ntdll.path());
    let nt_query = ntdll.dlsym("NtQueryInformationProcess".to_string());
    if !nt_query.is_null() {
        println!(
            "{}!NtQueryInformationProcess: {:#010x}",
            ntdll.name(),
            nt_query as usize
        );
    }

    // Parse the PE from its path on the disk
    if let Some(pe_on_disk) = ntdll.parse_from_path() {
        println!(
            "on-disk imagebase: {:#010x}",
            pe_on_disk.optional_header().imagebase()
        );
        if let Some(export) = pe_on_disk.export() {
            if let Some(entry) = export.entry_by_name("NtQueryInformationProcess") {
                println!("NtQueryInformationProcess: {:#010x}", entry.address());
            }
        }
    }

    // Parse the PE directly from memory
    if let Some(pe_memory) = ntdll.parse_from_memory() {
        let imagebase = pe_memory.optional_header().imagebase();
        println!("in-memory imagebase: {:#010x}", imagebase);
        if let Some(export) = pe_memory.export() {
            if let Some(entry) = export.entry_by_name("RtlFreeHeap") {
                let rva = entry.address() as u64;
                println!("RtlFreeHeap: {:#010x}", rva);

                // Disassemble the first instructions of RtlFreeHeap from memory
                for inst in runtime::disassemble(imagebase + rva).take(4) {
                    println!("    {}", inst.to_string());
                }
            }
        }
    }
    // lief-doc: modules-windows-end
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

    // Resolve kernel32 (loaded in every Windows process)
    let kernel32 = match runtime::windows::dlopen("kernel32.dll") {
        Some(m) => m,
        None => {
            eprintln!("Failed to dlopen kernel32.dll");
            let _ = chunk.deallocate();
            return;
        }
    };

    let p_get_std_handle = kernel32.dlsym("GetStdHandle".to_string());
    let p_write_file = kernel32.dlsym("WriteFile".to_string());
    if p_get_std_handle.is_null() || p_write_file.is_null() {
        eprintln!("Failed to resolve kernel32 symbols");
        let _ = chunk.deallocate();
        return;
    }
    let p_get_std_handle = p_get_std_handle as u64;
    let p_write_file = p_write_file as u64;

    // The message printed by the shellcode.
    const HELLO: &[u8] = b"Hello World\n";
    let msg_ptr = HELLO.as_ptr() as u64;
    let msg_len = HELLO.len() as u64;

    let mut config = AssemblerConfig::default();
    config.symbol_resolver = Some(Arc::new(move |name: &str| -> Option<u64> {
        match name {
            "GetStdHandle" => Some(p_get_std_handle),
            "WriteFile" => Some(p_write_file),
            "var_msg" => Some(msg_ptr),
            "var_msg_len" => Some(msg_len),
            _ => None,
        }
    }));

    // Shellcode dynamically compiled and whose referenced symbols are resolved
    // at runtime by the provided config
    let raw_inst = runtime::assemble_with_config(
        chunk.addr(),
        r#"
        .text
            .global main
            .align 2

        main:
            stp     x29, x30, [sp, -64]!
            mov     x29, sp
            stp     x19, x20, [sp, 16]
            stp     x21, x22, [sp, 32]

            // Here we use symbols that are **dynamically** resolved by the
            // AssemblerConfig
            ldr     x19, =GetStdHandle
            ldr     x20, =WriteFile
            ldr     x21, =var_msg
            ldr     w22, =var_msg_len

            // Call GetStdHandle(STD_OUTPUT_HANDLE)
            // STD_OUTPUT_HANDLE = -11
            // GetStdHandle is stored in x19
            mov     w0, -11
            blr     x19

            // Call ---> bool WriteFile(
            //   HANDLE  hConsoleOutput,        // x0: from GetStdHandle (already set)
            //   const VOID *lpBuffer,          // x1: pointer to string
            //   DWORD   nNumberOfCharsToWrite, // w2: length of string
            //   LPDWORD lpNumberOfCharsWritten,// x3: pointer to written count
            //   LPVOID  lpReserved             // x4: NULL
            // );
            mov     x1, x21
            mov     w2, w22
            add     x3, sp, 48
            mov     x4, xzr
            blr     x20

            mov     x0, xzr
            ldp     x21, x22, [sp, 32]
            ldp     x19, x20, [sp, 16]
            ldp     x29, x30, [sp], 64
            ret
        "#,
        &config,
    );

    println!(
        "{} bytes assembled at {:#010x}",
        raw_inst.len(),
        chunk.addr()
    );

    // Flush the instruction cache
    chunk.cache_flush();

    // Change the permission to R-X and invoke the JITed function
    chunk.make_rx();

    let hello_jit: unsafe extern "C" fn() = unsafe { std::mem::transmute(chunk.addr() as usize) };

    // This call prints the message "Hello World" on the console
    unsafe { hello_jit() };

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
