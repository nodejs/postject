use std::path::Path;
use std::process;

pub fn intro(path: &Path) {
    // lief-doc: intro-start
    let mut file = std::fs::File::open(path).expect("Can't open the file");

    if let Some(lief::Binary::PE(pe)) = lief::Binary::from(&mut file) {
        let rich_header = pe.rich_header().unwrap_or_else(|| {
            println!("Rich header not found!");
            process::exit(0);
        });

        println!("Rich header key: 0x{:x}", rich_header.key());
        for entry in rich_header.entries() {
            println!(
                "id: 0x{:04x} build_id: 0x{:04x} count: #{}",
                entry.id(),
                entry.build_id(),
                entry.count()
            );
        }

        let result = pe.verify_signature(lief::pe::signature::VerificationChecks::DEFAULT);
        if result == lief::pe::signature::VerificationFlags::OK {
            println!("Valid signature!");
        } else {
            println!("Signature not valid: {:?}", result);
        }
    }
    // lief-doc: intro-end
}
