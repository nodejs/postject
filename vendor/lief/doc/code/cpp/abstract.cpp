#include <memory>

#include <LIEF/Abstract/Binary.hpp>
#include <LIEF/Abstract/Parser.hpp>
#include <LIEF/ELF/Binary.hpp>

void parse_forms() {
  // lief-doc: parse-start
  std::unique_ptr<LIEF::Binary> target = LIEF::Parser::parse("some.elf");

  target = LIEF::Parser::parse("some.macho");

  target = LIEF::Parser::parse("some.exe");
  // lief-doc: parse-end
  (void)target;
}

void downcast() {
  // lief-doc: downcast-start
  std::unique_ptr<LIEF::Binary> target = LIEF::Parser::parse("some.elf");

  if (LIEF::ELF::Binary::classof(target.get())) {
    auto& elf = static_cast<LIEF::ELF::Binary&>(*target);
  }
  // lief-doc: downcast-end
}
