pub fn convert_to_dll(some_pe: &mut lief::pe::Binary) {
    // lief-doc: dll-header-start
    let pe: &mut lief::pe::Binary = some_pe;

    pe.header()
        .add_characteristic(lief::pe::headers::Characteristics::DLL);
    pe.optional_header().set_addressof_entrypoint(0);
    // lief-doc: dll-header-end
}

pub fn create_export_table(some_pe: &mut lief::pe::Binary) {
    // lief-doc: create-table-start
    let pe: &mut lief::pe::Binary = some_pe;

    let mut exp = lief::pe::Export::new();

    exp.set_name("lib_exe2dll.dll");
    exp.add_entry_by_name("cbk1", 0x0001000);
    exp.add_entry_by_name("cbk2", 0x0001010);

    pe.set_export(&exp);

    let mut config = lief::pe::builder::Config::default();
    config.exports = true;

    pe.write_with_config("lib_exe2dll.dll", config);
    // lief-doc: create-table-end
}

pub fn create_export_entries(some_pe: &mut lief::pe::Binary) {
    // lief-doc: create-entries-start
    let pe: &mut lief::pe::Binary = some_pe;

    let mut exp: lief::pe::Export = pe.export().unwrap();

    // Remove an entry
    exp.remove_entry_by_name("my_exported_name");

    // Add a new export
    exp.add_entry_by_name("fuzz_me", 0x10010);

    let mut config = lief::pe::builder::Config::default();
    config.exports = true;
    config.export_section = ".myedata".to_string();

    pe.write_with_config("out.dll", config);
    // lief-doc: create-entries-end
}
