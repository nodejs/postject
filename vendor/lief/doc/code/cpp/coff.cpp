#include <iostream>
#include <memory>

#include <LIEF/COFF.hpp>

void sections() {
  // lief-doc: sections-start
  std::unique_ptr<LIEF::COFF::Binary> coff;

  for (const LIEF::COFF::Section& section : coff->sections()) {
    std::cout << section.name() << '\n';
  }
  // lief-doc: sections-end
}

void disassemble() {
  // lief-doc: disassemble-start
  std::unique_ptr<LIEF::COFF::Binary> coff;

  for (const auto& inst : coff->disassemble("?foo@@YAHHH@Z")) {
    std::cout << inst.to_string() << '\n';
  }

  // Using demangled representation
  for (const auto& inst : coff->disassemble("int __cdecl bar(int, int)")) {
    std::cout << inst.to_string() << '\n';
  }
  // lief-doc: disassemble-end
}

void parse_forms() {
  // lief-doc: parse-start

  // Using a file path as a std::string
  std::unique_ptr<LIEF::COFF::Binary> coff = LIEF::COFF::Parser::parse("test.obj");
  // lief-doc: parse-end
}
