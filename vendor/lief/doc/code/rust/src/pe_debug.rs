pub fn change_name(some_pe: &mut lief::pe::Binary) {
    // lief-doc: change-name-start
    let pe: &mut lief::pe::Binary = some_pe;

    pe.codeview_pdb()
        .unwrap()
        .set_filename(r#"C:\A\B\C\path.pdb"#);

    pe.write("out.exe");
    // lief-doc: change-name-end
}

pub fn add(some_pe: &mut lief::pe::Binary) {
    // lief-doc: add-start
    let pe: &mut lief::pe::Binary = some_pe;

    let cv = lief::pe::debug::CodeViewPDB::with_filename("MyCustom.pdb");

    pe.add_debug_info(&cv);

    pe.write("out.exe");
    // lief-doc: add-end
}

pub fn remove(some_pe: &mut lief::pe::Binary) {
    // lief-doc: remove-start
    let pe: &mut lief::pe::Binary = some_pe;

    // Remove a single CodeViewPDB entry
    if let Some(cv_pdb) = pe.codeview_pdb() {
        todo!("Not Implemented yet");
        //pe.remove_debug(cv_pdb);
    }

    // Remove all entries
    pe.clear_debug();

    pe.write("out.exe");
    // lief-doc: remove-end
}
