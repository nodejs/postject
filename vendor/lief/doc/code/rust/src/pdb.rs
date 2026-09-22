use std::path::{Path, PathBuf};
use std::process;

use lief::generic::Binary;
use lief::pdb::types::PdbType;

pub fn load_pdb(some_pe: &lief::pe::Binary) {
    // lief-doc: load-start
    let pe: &lief::pe::Binary = some_pe;
    if let Some(lief::DebugInfo::Pdb(pdb)) = pe.debug_info() {
        // PDB debug info
    }

    let pdb = lief::pdb::load("some.pdb");
    // lief-doc: load-end
}

pub fn load_ext(some_bin: &mut dyn lief::generic::Binary) {
    // lief-doc: load-ext-start
    let bin: &mut dyn lief::generic::Binary = some_bin;

    let path = PathBuf::from("C:\\Users\\romain\\LIEF.pdb");

    bin.load_debug_info(&path);
    // lief-doc: load-ext-end
}

pub fn disassemble(some_bin: &mut dyn lief::generic::Binary) {
    // lief-doc: disassemble-start
    let bin: &mut dyn lief::generic::Binary = some_bin;

    let path = PathBuf::from("C:\\Users\\romain\\LIEF.pdb");

    bin.load_debug_info(&path);

    // The location (address/size) of `my_function` is defined in LIEF.pdb
    for inst in bin.disassemble_symbol("my_function") {
        println!("{inst}");
    }
    // lief-doc: disassemble-end
}

pub fn to_decl(some_pdb: &lief::pdb::DebugInfo) {
    // lief-doc: to-decl-start
    let pdb: &lief::pdb::DebugInfo = some_pdb;

    let opt = lief::DeclOpt {
        is_cpp: true,
        ..Default::default()
    };

    for ty in pdb.types() {
        println!("{}", ty.to_decl_with_opt(&opt));
    }

    for cu in pdb.compilation_units() {
        println!("{}", cu.to_decl_with_opt(&opt));
        for func in cu.functions() {
            println!("{}", func.to_decl_with_opt(&opt));
        }
    }
    // lief-doc: to-decl-end
}

pub fn explore(path: &Path) {
    // lief-doc: explore-start
    let pdb = lief::pdb::load(path).unwrap_or_else(|| {
        process::exit(1);
    });

    println!("age={}, guid={}", pdb.age(), pdb.guid());

    for symbol in pdb.public_symbols() {
        println!(
            "name={}, section={}, RVA={}",
            symbol.name(),
            symbol.section_name().unwrap_or("".to_string()),
            symbol.rva()
        );
    }

    for ty in pdb.types() {
        if let lief::pdb::Type::Class(clazz) = ty {
            println!("Class[name]={}", clazz.name().unwrap_or_default());
        }
    }

    for cu in pdb.compilation_units() {
        println!("module={}", cu.module_name());
        for src in cu.sources() {
            println!("  - {}", src);
        }

        for func in cu.functions() {
            println!(
                "name={}, section={}, RVA={}, code_size={}",
                func.name(),
                func.section_name(),
                func.rva(),
                func.code_size()
            );
        }
    }
    // lief-doc: explore-end
}
