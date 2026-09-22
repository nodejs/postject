use lief::generic::Binary;
use lief::macho::commands::RPath;

pub fn iterate(some_fat: &lief::macho::FatBinary) {
    // lief-doc: iterate-start
    let fat: &lief::macho::FatBinary = some_fat;

    // Iterate
    for macho in fat.iter() {
        println!("{}", macho.entrypoint());
    }

    // Pick one with the given arch
    let arm64 = fat
        .with_cpu(lief::macho::header::CpuType::ARM64)
        .expect("Missing ARM64");
    // lief-doc: iterate-end
}

pub fn write_bytes(some_macho: &mut lief::macho::Binary) {
    // lief-doc: write-bytes-start
    let macho: &mut lief::macho::Binary = some_macho;

    let bytes: Vec<u8> = macho.write_to_bytes();
    // lief-doc: write-bytes-end
}

pub fn parse_from_dump() {
    // lief-doc: dump-start
    let fat = lief::macho::FatBinary::parse_from_dump("module.dump", 0x1_1e32_c000).unwrap();
    let macho = fat.iter().next().unwrap();

    for segment in macho.segments() {
        println!("{} {:#x}", segment.name(), segment.virtual_address());
    }
    // lief-doc: dump-end
}

pub fn module_dump() {
    // lief-doc: dump-runtime-start
    use lief::runtime::Module;

    let module = lief::runtime::module_from_name("libsystem_c.dylib").unwrap();

    // Dump the module's memory into a file (the raw bytes are also returned)
    let data = module.dump_to_file("module.dump");

    let fat = lief::macho::FatBinary::parse_from_dump("module.dump", module.imagebase()).unwrap();
    // lief-doc: dump-runtime-end
}

pub fn rpath_change_lib() {
    // lief-doc: rpath-change-lib-start
    let fat = lief::macho::FatBinary::parse("hello.bin").unwrap();
    let mut binary = fat.iter().next().unwrap();

    let mut lib = binary.find_library("libmylib.dylib").unwrap();
    lib.set_name("/opt/homebrew/my_package/libmylib.dylib");

    binary.write("hello_fixed.bin");
    // lief-doc: rpath-change-lib-end
}

pub fn rpath_add() {
    // lief-doc: rpath-add-start
    let fat = lief::macho::FatBinary::parse("hello.bin").unwrap();
    let mut binary = fat.iter().next().unwrap();

    let rpath = RPath::new("/opt/homebrew/my_package");
    binary.add_command(rpath);
    // lief-doc: rpath-add-end
}

pub fn rpath_atrpath(some_binary: &mut lief::macho::Binary) {
    // lief-doc: rpath-atrpath-start
    let binary: &mut lief::macho::Binary = some_binary;

    let mut lib = binary.find_library("libmylib.dylib").unwrap();
    lib.set_name("@rpath/libmylib.dylib");

    binary.write("hello_fixed.bin");
    // lief-doc: rpath-atrpath-end
}

pub fn parse_forms() {
    // lief-doc: parse-start
    let macho: lief::macho::FatBinary = lief::macho::FatBinary::parse("/bin/ls").unwrap();
    // lief-doc: parse-end
}

pub fn write_fat(some_fat: &mut lief::macho::FatBinary) {
    // lief-doc: write-fat-start
    let fat: &mut lief::macho::FatBinary = some_fat;
    fat.with_cpu(lief::macho::header::CpuType::ARM64)
        .unwrap()
        .write("fit.macho");
    // lief-doc: write-fat-end
}

pub fn advanced_parse_write() {
    // lief-doc: advanced-start
    let mut parser_config = lief::macho::ParserConfig::default();
    parser_config.parse_dyld_bindings = false;

    let mut fat = lief::macho::parse_with_config("my.macho", &parser_config).unwrap();

    let mut macho = fat.iter().next().unwrap();

    let mut builder_config = lief::macho::builder::Config::default();
    builder_config.linkedit = false;

    macho.write_with_config("new.macho", builder_config);
    // lief-doc: advanced-end
}
