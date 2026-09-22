use std::process;

pub fn check(some_macho: &lief::macho::Binary) {
    // lief-doc: check-start
    let macho: &lief::macho::Binary = some_macho;

    if let Some(metadata) = macho.objc_metadata() {
        println!("Objective-C metadata found");
    }
    // lief-doc: check-end
}

pub fn inspect(some_macho: &lief::macho::Binary) {
    // lief-doc: inspect-start
    let macho: &lief::macho::Binary = some_macho;

    let Some(metadata) = macho.objc_metadata() else {
        process::exit(1);
    };

    for class in metadata.classes() {
        println!("name={}", class.name());
        for method in class.methods() {
            println!("  method.name={}", method.name());
        }
    }
    println!("{}", metadata.to_decl());
    // lief-doc: inspect-end
}

// lief-doc: classdump-start
fn classdump(macho: &lief::macho::Binary) {
    let metadata = macho.objc_metadata().expect("Missing Objective-C info");
    for class in metadata.classes() {
        println!("{}", class.to_decl());
    }
}
// lief-doc: classdump-end
