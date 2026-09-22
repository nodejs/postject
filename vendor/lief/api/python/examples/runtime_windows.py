#!/usr/bin/env python3
import ctypes
import sys
from itertools import islice

import lief


def host_info():
    print("Host")
    # lief-doc: host-start
    print(f"    Hostname: {lief.runtime.Host.name}")
    print(f"    Home:     {lief.runtime.Host.home_dir}")
    print(f"    Cache:    {lief.runtime.Host.cache_dir}")
    print(f"    Temp:     {lief.runtime.Host.tmp_dir}")
    print(f"    Config:   {lief.runtime.Host.config_dir}")
    # lief-doc: host-end

    # lief-doc: host-windows-start
    print(f"    Version:  {lief.runtime.windows.Host.version}")
    # lief-doc: host-windows-end
    print()


def process_info():
    print("Process")
    # lief-doc: process-start
    print(f"    PID:       {lief.runtime.Process.pid}")
    print(f"    TID:       {lief.runtime.Process.tid}")
    print(f"    Page size: {lief.runtime.Process.page_size:#06x}")
    print(f"    Arch:      {lief.runtime.Process.arch}")
    print(f"    Platform:  {lief.runtime.Process.platform}")
    if (userdomain := lief.runtime.Process.get_env("USERDOMAIN")) is not None:
        print(f"    USERDOMAIN:{userdomain}")
    # lief-doc: process-end

    # lief-doc: process-windows-start
    if (peb := lief.runtime.windows.Process.peb) is not None:
        print(f"    PEB.BeingDebugged:          {peb.being_debugged}")
        print(f"    PEB.Ldr:                    {peb.ldr:#06x}")
        print(f"    PEB.ProcessParameters:      {peb.process_parameters:#06x}")
        print(f"    PEB.AtlThunkSListPtr:       {peb.atl_thunk_slist_ptr:#06x}")
        print(f"    PEB.AtlThunkSListPtr32:     {peb.atl_thunk_slist_ptr32:#06x}")
        print(f"    PEB.PostProcessInitRoutine: {peb.post_process_init_routine:#06x}")
        print(f"    PEB.SessionId:              {peb.session_id:#06x}")
    # lief-doc: process-windows-end

    # lief-doc: peb-modules-start
    if (peb := lief.runtime.windows.Process.peb) is not None:
        modules = list(peb.entries)
        for i, entry in enumerate(modules[:3]):
            print(
                f"    module[{i}]: {entry.base_dll_name} "
                f"(base={entry.dll_base:#06x}, size={entry.size_of_image:#06x})"
            )
        print(f"    -> {len(modules)} modules in the load order list")
        if modules:
            print(f"    last module: {modules[-1].base_dll_name}")
    # lief-doc: peb-modules-end

    # lief-doc: peb-module-details-start
    if (peb := lief.runtime.windows.Process.peb) is not None:
        first = next(iter(peb.entries), None)
        if first is not None:
            print(f"    {first.base_dll_name} extended LDR_DATA_TABLE_ENTRY fields:")
            # Always available across the supported Windows versions:
            print(f"      Flags:             {first.flags:#06x}")
            print(f"      ObsoleteLoadCount: {first.obsolete_load_count}")
            print(f"      TlsIndex:          {first.tls_index:#06x}")
            print(f"      TimeDateStamp:     {first.time_date_stamp:#06x}")
            # Attributes that are available only from certain version:
            if (v := first.ddag_node) is not None:  # Windows 8+
                print(f"      DdagNode:          {v:#06x}")
            if (v := first.original_base) is not None:  # Windows 8+
                print(f"      OriginalBase:      {v:#06x}")
            if (v := first.load_reason) is not None:  # Windows 8+
                print(f"      LoadReason:        {v}")
            if (v := first.signing_level) is not None:  # Windows 10+
                print(f"      SigningLevel:      {v}")
            if (v := first.check_sum) is not None:  # Windows 10+
                print(f"      CheckSum:          {v:#06x}")
            if (v := first.hot_patch_state) is not None:  # Windows 11+
                print(f"      HotPatchState:     {v}")
    # lief-doc: peb-module-details-end


def modules_info():
    print("Module API")
    ntdll: lief.runtime.windows.Module | None = None
    # lief-doc: modules-start
    for mod in lief.runtime.modules():
        print(mod)
        # Look for ntdll
        if mod.name.endswith("ntdll.dll"):
            print(
                f"ntdll.dll found: {mod.path} ([{mod.imagebase:#010x}, {mod.end:#010x}])"
            )
            assert isinstance(mod, lief.runtime.windows.Module)
            ntdll = mod
    # lief-doc: modules-end

    if ntdll is None:
        return

    # lief-doc: modules-windows-start
    print(f"ntdll path: {ntdll.path}")
    if nt_query := ntdll.dlsym("NtQueryInformationProcess"):
        # lief.to_int converts an opaque pointer (void*) into a regular Python int
        nt_query_addr = lief.to_int(nt_query)
        print(f"{ntdll.name}!NtQueryInformationProcess: {nt_query_addr:#010x}")

    # This parses the PE from its path on the disk
    if pe_on_disk := ntdll.parse_from_path():
        print(f"on-disk imagebase: {pe_on_disk.optional_header.imagebase:#010x}")
        if sym := pe_on_disk.get_symbol("NtQueryInformationProcess"):
            print(f"NtQueryInformationProcess: {sym.value:#010x}")

    # This parses the PE directly from memory
    if pe_memory := ntdll.parse_from_memory():
        imagebase = pe_memory.optional_header.imagebase
        print(f"in-memory imagebase: {imagebase:#010x}")
        if sym := pe_memory.get_symbol("RtlFreeHeap"):
            print(f"RtlFreeHeap: {sym.value:#010x}")

            # With LIEF extended, we can disassemble the function directly from
            # its absolute memory address:
            if lief.__extended__:
                for inst in islice(lief.runtime.disassemble(imagebase + sym.value), 4):
                    print("   ", inst)
    # lief-doc: modules-windows-end


def memory_example():
    print("Memory")
    # lief-doc: memory-start
    chunk = lief.runtime.Memory.mmap(
        lief.runtime.Process.page_size,
        lief.runtime.Memory.ANONYMOUS | lief.runtime.Memory.PRIVATE,
        lief.runtime.Memory.READ | lief.runtime.Memory.WRITE | lief.runtime.Memory.EXEC,
    )

    # The message printed by the shellcode. It must stay alive while the JITed
    # function runs, so we keep a reference for the whole function.
    MSG = b"Hello World\n"
    msg = ctypes.create_string_buffer(MSG)

    # The assembler resolves the symbols referenced by the shellcode through
    # this config, mirroring the C++ ``AssemblerConfig::resolve_symbol`` override.
    class Config(lief.assembly.AssemblerConfig):
        def resolve_symbol(self, name: str) -> int | None:
            kernel32 = lief.runtime.windows.dlopen("kernel32.dll")
            if kernel32 is None:
                print("Failed to dlopen kernel32.dll", file=sys.stderr)
                return None

            # Resolve the symbols that are used by the shellcode
            if name == "GetStdHandle":
                return lief.to_int(kernel32.dlsym("GetStdHandle"))
            if name == "WriteFile":
                return lief.to_int(kernel32.dlsym("WriteFile"))
            if name == "var_msg":
                return ctypes.addressof(msg)
            if name == "var_msg_len":
                return len(MSG)
            return None

    config = Config()

    # Shellcode dynamically compiled and whose referenced symbols are resolved
    # at runtime by the provided config
    lief.runtime.assemble(
        chunk.addr,
        r"""
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
        """,
        config,
    )

    # Flush the instruction cache
    chunk.cache_flush()

    # Change the permission to R-X and invoke the JITed function
    chunk.make_rx()

    void_void_func = ctypes.CFUNCTYPE(None)  # void(*)()
    hello_jit = void_void_func(chunk.addr)

    # This call prints the message "Hello World" on the console
    hello_jit()

    # Don't miss good practices!
    chunk.deallocate()
    # lief-doc: memory-end


def main() -> int:
    if not lief.runtime.enabled:
        print("Error: LIEF's runtime is not enabled", file=sys.stderr)
        return 0

    host_info()
    process_info()
    modules_info()
    memory_example()
    return 0


if __name__ == "__main__":
    sys.exit(main())
