pub fn sections(some_coff: &lief::coff::Binary) {
    // lief-doc: sections-start
    let coff: &lief::coff::Binary = some_coff;

    for section in coff.sections() {
        println!("{section:?} {section}");
    }
    // lief-doc: sections-end
}

pub fn disassemble(some_coff: &lief::coff::Binary) {
    // lief-doc: disassemble-start
    let coff: &lief::coff::Binary = some_coff;

    for inst in coff.disassemble_function("?foo@@YAHHH@Z") {
        println!("{}", inst);
    }

    // Using demangled representation
    for inst in coff.disassemble_function("int __cdecl bar(int, int)") {
        println!("{}", inst);
    }
    // lief-doc: disassemble-end
}

pub fn parse_forms() {
    // lief-doc: parse-start
    let coff: lief::coff::Binary = lief::coff::Binary::parse("test.obj").unwrap();
    // lief-doc: parse-end
}
