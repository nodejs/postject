use std::path::PathBuf;

use lief::elf::dynamic;
use lief::generic::Section;

pub fn inspect(some_elf: &lief::elf::Binary) {
    // lief-doc: inspect-start
    let elf: &lief::elf::Binary = some_elf;

    println!("{}", elf.header().entrypoint());

    for section in elf.sections() {
        println!("{} {}", section.name(), section.content().len());
    }
    // lief-doc: inspect-end
}

pub fn modify_write(some_elf: &mut lief::elf::Binary) {
    // lief-doc: write-start
    let elf: &mut lief::elf::Binary = some_elf;

    elf.add_library("libdemo.so");
    elf.write("new.elf");
    // lief-doc: write-end
}

pub fn write_bytes(some_elf: &mut lief::elf::Binary) {
    // lief-doc: write-bytes-start
    let elf: &mut lief::elf::Binary = some_elf;

    let bytes: Vec<u8> = elf.write_to_bytes();
    // lief-doc: write-bytes-end
}

pub fn add_loaded_segment(some_elf: &mut lief::elf::Binary) {
    // lief-doc: add-segment-start
    let elf: &mut lief::elf::Binary = some_elf;

    let mut segment = lief::elf::Segment::new();
    segment.set_type(lief::elf::segment::Type::LOAD);
    segment.set_content(&[1, 2, 3]);

    elf.add_segment(&segment);
    elf.write("new.elf");
    // lief-doc: add-segment-end
}

pub fn add_loaded_section(some_elf: &mut lief::elf::Binary) {
    // lief-doc: add-section-loaded-start
    let elf: &mut lief::elf::Binary = some_elf;

    let section = lief::elf::Section::new_with_content(".lief_demo", &[1, 2, 3]);

    elf.add_section(
        &section,
        /* loaded= */ true,
        lief::elf::binary::SecInsertPos::AUTO,
    );
    elf.write("new.elf");
    // lief-doc: add-section-loaded-end
}

pub fn add_unloaded_section(some_elf: &mut lief::elf::Binary) {
    // lief-doc: add-section-unloaded-start
    let elf: &mut lief::elf::Binary = some_elf;

    let section = lief::elf::Section::new_with_content(".metadata", b"version: 1.2.3");

    // /!\ Note that loaded is set to false here
    // -----------------------------------------
    elf.add_section(
        &section,
        /* loaded= */ false,
        lief::elf::binary::SecInsertPos::AUTO,
    );
    elf.write("new.elf");
    // lief-doc: add-section-unloaded-end
}

pub fn parse_from_dump() {
    // lief-doc: dump-start
    let elf = lief::elf::Binary::parse_from_dump("module.dump", 0x7f9b_98e0_0000).unwrap();

    for segment in elf.segments() {
        println!("{:?} {:#x}", segment.p_type(), segment.virtual_address());
    }
    // lief-doc: dump-end
}

pub fn module_dump() {
    // lief-doc: dump-runtime-start
    use lief::runtime::Module;

    let module = lief::runtime::module_from_name("libc.so.6").unwrap();

    // Dump the module's memory into a file (the raw bytes are also returned)
    let data = module.dump_to_file("module.dump");

    let elf = lief::elf::Binary::parse_from_dump("module.dump", module.imagebase()).unwrap();
    // lief-doc: dump-runtime-end
}

pub fn advanced_parse_write() {
    // lief-doc: advanced-start
    let mut parser_config = lief::elf::ParserConfig::default();
    parser_config.parse_overlay = false;

    let mut elf = lief::elf::parse_with_config("my.elf", &parser_config).unwrap();

    let mut builder_config = lief::elf::builder::Config::default();
    builder_config.gnu_hash = false;

    elf.write_with_config("new.elf", builder_config);
    // lief-doc: advanced-end
}

pub fn rpath_add(some_elf: &mut lief::elf::Binary) {
    // lief-doc: rpath-add-start
    let elf: &mut lief::elf::Binary = some_elf;

    let runpath = lief::elf::dynamic::RunPath::new("$ORIGIN:/opt/lib64");

    elf.add_dynamic_entry(&runpath);

    let other_runpath = lief::elf::dynamic::RunPath::with_paths(&["$ORIGIN", "/opt/lib64"]);

    elf.add_dynamic_entry(&other_runpath);

    let output = PathBuf::from("updated.elf");

    elf.write(output.as_path());
    // lief-doc: rpath-add-end
}

pub fn rpath_change(some_elf: &mut lief::elf::Binary) {
    // lief-doc: rpath-change-start
    let elf: &mut lief::elf::Binary = some_elf;

    if let Some(dynamic::Entries::RunPath(mut runpath)) =
        elf.dynamic_entry_by_tag(dynamic::Tag::RUNPATH)
    {
        runpath.set_runpath("$ORIGIN:/opt/lib64");
        runpath.append("lib-x86_64-gnu");
    }

    let output = PathBuf::from("updated.elf");

    elf.write(output.as_path());
    // lief-doc: rpath-change-end
}

pub fn rpath_remove(some_elf: &mut lief::elf::Binary) {
    // lief-doc: rpath-remove-start
    let elf: &mut lief::elf::Binary = some_elf;

    // Remove **all** DT_RUNPATH entries
    elf.remove_dynamic_entries_by_tag(dynamic::Tag::RUNPATH);

    // Remove all entries that contain '$ORIGIN'
    elf.remove_dynamic_entry_if(|e| {
        if let dynamic::Entries::RunPath(runpath) = e {
            return runpath.runpath().contains("$ORIGIN");
        }
        false
    });

    let output = PathBuf::from("updated.elf");
    elf.write(output.as_path());
    // lief-doc: rpath-remove-end
}

pub fn symver_remove_symbol(some_elf: &mut lief::elf::Binary) {
    // lief-doc: symver-symbol-start
    let elf: &mut lief::elf::Binary = some_elf;

    if let Some(sym) = elf.dynamic_symbol_by_name("printf")
        && let Some(mut symver) = sym.symbol_version()
    {
        symver.as_global();
    }

    let output = PathBuf::from("updated.elf");
    elf.write(output.as_path());
    // lief-doc: symver-symbol-end
}

pub fn symver_remove_library(some_elf: &mut lief::elf::Binary) {
    // lief-doc: symver-library-start
    let elf: &mut lief::elf::Binary = some_elf;

    elf.remove_version_requirement("libm.so.6");

    let output = PathBuf::from("updated.elf");
    elf.write(output.as_path());
    // lief-doc: symver-library-end
}

pub fn parse_forms() {
    // lief-doc: parse-start
    let elf: lief::elf::Binary = lief::elf::Binary::parse("/bin/ls").unwrap();
    // lief-doc: parse-end
}
