use std::path::{Path, PathBuf};
use std::process;

use lief::dwarf::editor::types::EditorType;
use lief::dwarf::types::DwarfType;
use lief::generic::Binary;

pub fn embedded() {
    // lief-doc: embedded-start
    let elf = lief::elf::Binary::parse("/bin/ls").unwrap();
    if let Some(lief::DebugInfo::Dwarf(dwarf)) = elf.debug_info() {
        // DWARF debug info
    }
    // lief-doc: embedded-end
}

pub fn load() {
    // lief-doc: load-start
    let dbg = lief::dwarf::load("/bin/with_debug");
    let dbg = lief::dwarf::load("external_dwarf");
    let dbg = lief::dwarf::load("debug.dwo");
    // lief-doc: load-end
}

pub fn iterate(some_path: &Path) {
    // lief-doc: iterate-start
    let path: &Path = some_path;

    let dbg = lief::dwarf::load(path).unwrap_or_else(|| {
        process::exit(1);
    });

    for cu in dbg.compilation_units() {
        println!("Producer: {}", cu.producer());
        for func in cu.functions() {
            println!(
                "name={}, linkage={}, address={}",
                func.name(),
                func.linkage_name(),
                func.address().unwrap_or(0)
            );
        }

        for var in cu.variables() {
            println!(
                "name={}, address={}",
                var.name(),
                var.address().unwrap_or(0)
            );
        }

        for ty in cu.types() {
            println!(
                "name={}, size={}",
                ty.name().unwrap_or("".to_string()),
                ty.size().unwrap_or(0)
            );
        }
    }

    dbg.function_by_name("_ZNSi4peekEv");
    dbg.function_by_name("std::basic_istream<char, std::char_traits<char> >::peek()");
    dbg.function_by_addr(0x137a70);

    dbg.variable_by_name("_ZNSt12out_of_rangeC1EPKc");
    dbg.variable_by_name("std::out_of_range::out_of_range(char const*)");
    dbg.variable_by_addr(0x137a70);
    // lief-doc: iterate-end
}

pub fn load_external(some_bin: &mut dyn lief::generic::Binary) {
    // lief-doc: load-external-start
    let bin: &mut dyn lief::generic::Binary = some_bin;

    let path = PathBuf::from("/home/romain/dev/LIEF/some.dwo");

    bin.load_debug_info(&path);
    // lief-doc: load-external-end
}

pub fn disassemble_external(some_bin: &mut dyn lief::generic::Binary) {
    // lief-doc: disassemble-start
    let bin: &mut dyn lief::generic::Binary = some_bin;

    let path = PathBuf::from("/home/romain/dev/LIEF/some.dwo");

    bin.load_debug_info(&path);

    // The location (address/size) of `my_function` is defined in some.dwo
    for inst in bin.disassemble_symbol("my_function") {
        println!("{inst}");
    }
    // lief-doc: disassemble-end
}

pub fn to_decl() {
    // lief-doc: to-decl-start
    let dbg = lief::dwarf::load("/bin/with_debug").unwrap();

    if let Some(func) = dbg.function_by_name("main") {
        println!("{}", func.to_decl());
    }

    let opt = lief::DeclOpt {
        is_cpp: true,
        indentation: 4,
        ..Default::default()
    };
    for cu in dbg.compilation_units() {
        println!("{}", cu.to_decl_with_opt(&opt));
    }
    // lief-doc: to-decl-end
}

pub fn editor_from_binary(some_path: &Path) {
    // lief-doc: editor-from-binary-start
    let path: &Path = some_path;

    let mut bin = lief::pe::Binary::parse(path).unwrap();
    let editor = lief::dwarf::Editor::from_binary(&mut bin);
    // lief-doc: editor-from-binary-end
}

pub fn editor_create(some_editor: &mut lief::dwarf::Editor) {
    // lief-doc: editor-create-start
    let editor: &mut lief::dwarf::Editor = some_editor;

    let mut unit = editor.create_compile_unit().unwrap();
    unit.set_producer("LIEF");

    let mut func = unit.create_function("hello").unwrap();
    func.set_address(0x123);
    func.set_return_type(&unit.create_structure("my_struct_t").pointer_to());

    let mut var = func.create_stack_variable("local_var");
    var.set_stack_offset(8);

    editor.write("/tmp/out.debug");
    // lief-doc: editor-create-end
}
