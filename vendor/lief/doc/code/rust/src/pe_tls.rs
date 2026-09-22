pub fn modify_callbacks(some_pe: &mut lief::pe::Binary) {
    // lief-doc: modify-callbacks-start
    let pe: &mut lief::pe::Binary = some_pe;

    let mut tls = pe.tls().unwrap();

    let mut callbacks: Vec<u64> = tls.callbacks();

    // Remove the last entry
    callbacks.pop();

    // Add an address
    callbacks.push(0x140001010);

    tls.set_callbacks(&callbacks);

    pe.write("tls_modified.exe");
    // lief-doc: modify-callbacks-end
}

pub fn create_tls() {
    // lief-doc: create-tls-start
    let mut tls = lief::pe::TLS::new();

    tls.set_callbacks(&[0x140001000, 0x140001010]);
    // lief-doc: create-tls-end
}

pub fn add_tls(pe: &mut lief::pe::Binary) {
    let tls = lief::pe::TLS::new();
    // lief-doc: add-tls-start
    pe.set_tls(&tls); // `tls` defined previously

    pe.write("tls_demo.exe");
    // lief-doc: add-tls-end
}
