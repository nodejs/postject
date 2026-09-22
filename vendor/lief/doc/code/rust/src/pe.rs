use lief::generic::Section;

pub fn inspect(some_pe: &lief::pe::Binary) {
    // lief-doc: inspect-start
    let pe: &lief::pe::Binary = some_pe;

    println!("{:?}", pe.rich_header().expect("Missing Rich header"));

    for section in pe.sections() {
        println!("{} {}", section.name(), section.content().len());
    }
    // lief-doc: inspect-end
}

pub fn add_section() {
    // lief-doc: add-section-start
    let mut pe = lief::pe::Binary::parse("some.exe").unwrap();

    let mut section = lief::pe::Section::new_with_name(".hello");
    section.set_content(&[0xCC; 0x100]);
    pe.add_section(section);

    pe.write("new.exe");
    // lief-doc: add-section-end
}

pub fn parse_from_dump() {
    // lief-doc: dump-start
    let pe = lief::pe::Binary::parse_from_dump("module.dump", 0x7ffd_21b8_0000).unwrap();

    for imp in pe.imports() {
        println!("{}", imp.name());
    }
    // lief-doc: dump-end
}

pub fn module_dump() {
    // lief-doc: dump-runtime-start
    use lief::runtime::Module;

    let module = lief::runtime::module_from_name("target.dll").unwrap();

    // Dump the module's memory into a file (the raw bytes are also returned)
    let data = module.dump_to_file("module.dump");

    let pe = lief::pe::Binary::parse_from_dump("module.dump", module.imagebase()).unwrap();
    // lief-doc: dump-runtime-end
}

pub fn advanced_parse_write() {
    // lief-doc: advanced-start
    let mut parser_config = lief::pe::parser_config::Config::default();
    parser_config.parse_signature = false;

    let mut pe = lief::pe::parse_with_config("some.exe", &parser_config).unwrap();

    let mut config = lief::pe::builder::Config::default();
    config.imports = true;

    pe.write_with_config("new.exe", config);
    // lief-doc: advanced-end
}

pub fn write_bytes(some_pe: &mut lief::pe::Binary) {
    // lief-doc: write-bytes-start
    let pe: &mut lief::pe::Binary = some_pe;

    let bytes: Vec<u8> = pe.write_to_bytes();
    // lief-doc: write-bytes-end
}

pub fn authenticode() {
    // lief-doc: authenticode-start
    if let Some(lief::Binary::PE(pe)) = lief::Binary::parse("signed.exe") {
        for sig in pe.signatures() {
            for crt in sig.certificates() {
                println!("{:?}", crt);
            }
        }

        assert!(
            pe.verify_signature(lief::pe::signature::VerificationChecks::DEFAULT)
                == lief::pe::signature::VerificationFlags::OK
        );
    }
    // lief-doc: authenticode-end
}

pub fn parse_forms() {
    // lief-doc: parse-start
    let pe: lief::pe::Binary = lief::pe::Binary::parse("/bin/ls").unwrap();
    // lief-doc: parse-end
}
