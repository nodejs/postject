pub fn remove_import(some_pe: &mut lief::pe::Binary) {
    // lief-doc: remove-import-start
    let pe: &mut lief::pe::Binary = some_pe;

    pe.remove_import("kernel32.dll");

    let mut config = lief::pe::builder::Config::default();
    config.imports = true;

    pe.write_with_config("new.exe", config);
    // lief-doc: remove-import-end
}

pub fn remove_import_entry(some_pe: &mut lief::pe::Binary) {
    // lief-doc: remove-import-entry-start
    let pe: &mut lief::pe::Binary = some_pe;

    if let Some(mut kernel32) = pe.import_by_name("kernel32.dll") {
        kernel32.remove_entry_by_name("IsDebuggerPresent");
    }

    let mut config = lief::pe::builder::Config::default();
    config.imports = true;

    pe.write_with_config("new.exe", config);
    // lief-doc: remove-import-entry-end
}

pub fn add_import(some_pe: &mut lief::pe::Binary) {
    // lief-doc: add-import-start
    let pe: &mut lief::pe::Binary = some_pe;

    let mut stdio = pe.add_import("api-ms-win-crt-stdio-l1-1-0.dll");
    let _puts = stdio.add_entry_by_name("puts");

    let mut config = lief::pe::builder::Config::default();
    config.imports = true;

    pe.write_with_config("new.exe", config);
    // lief-doc: add-import-end
}

pub fn add_import_func(some_pe: &mut lief::pe::Binary) {
    // lief-doc: add-import-func-start
    let pe: &mut lief::pe::Binary = some_pe;

    let mut kernel32 = pe.add_import("kernel32.dll");
    let _get_startup_info = kernel32.add_entry_by_name("GetStartupInfoW");

    let mut config = lief::pe::builder::Config::default();
    config.imports = true;

    pe.write_with_config("new.exe", config);
    // lief-doc: add-import-func-end
}
