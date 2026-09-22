/// This example shows how to disassemble an ELF/PE/Mach-O binary using LIEF's extended API
use lief::assembly::Instruction;
use std::process::ExitCode;

fn disassemble(target: &dyn lief::generic::Binary, address: u64) -> ExitCode {
    for inst in target.disassemble_address(address) {
        println!("{inst}");
    }
    ExitCode::SUCCESS
}

fn main() -> ExitCode {
    if !lief::is_extended() {
        println!("This example requires the extended version of LIEF");
        return ExitCode::FAILURE;
    }

    let args = Vec::from_iter(std::env::args());
    if args.len() != 3 {
        println!("Usage: {} <binary> <address>", args[0]);
        // Disassemble the disassemble() itself
        for inst in lief::runtime::disassemble((disassemble as usize).try_into().unwrap()) {
            println!("{inst}");
            if inst.is_return() {
                break;
            }
        }
        return ExitCode::FAILURE;
    }

    let path = &args[1];
    let addr_str = &args[2];

    let addr = {
        if addr_str.starts_with("0x") {
            u64::from_str_radix(addr_str.trim_start_matches("0x"), 16).unwrap()
        } else {
            addr_str.parse::<u64>().unwrap()
        }
    };

    let bin = lief::Binary::parse(path).expect("Can't parse the binary");
    match bin {
        lief::Binary::ELF(elf) => disassemble(&elf, addr),

        lief::Binary::PE(pe) => disassemble(&pe, addr),

        lief::Binary::MachO(fat) => {
            let fit = fat.iter().next().unwrap();
            disassemble(&fit, addr)
        }
        lief::Binary::COFF(_) => ExitCode::SUCCESS,
    }
}
