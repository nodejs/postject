#include <cstdint>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include <LIEF/PE.hpp>
#include <LIEF/runtime.hpp>

using namespace LIEF::PE;

void inspect() {
  // lief-doc: inspect-start
  std::unique_ptr<LIEF::PE::Binary> pe;

  if (const LIEF::PE::RichHeader* rich = pe->rich_header()) {
    std::cout << *rich << '\n';
  }

  for (const LIEF::PE::Section& section : pe->sections()) {
    std::cout << section.name() << section.content().size() << '\n';
  }
  // lief-doc: inspect-end
}

void add_section() {
  // lief-doc: add-section-start
  std::unique_ptr<LIEF::PE::Binary> pe;

  LIEF::PE::Section section(".hello");
  section.content(std::vector<uint8_t>(0x100, 0xCC));
  pe->add_section(section);

  pe->write("new.exe");
  // lief-doc: add-section-end
}

void parse_from_dump() {
  // lief-doc: dump-start
  auto pe = LIEF::PE::Parser::parse_from_dump("module.dump", 0x7ffd21b80000);

  for (const LIEF::PE::Import& imp : pe->imports()) {
    std::cout << imp.name() << '\n';
  }
  // lief-doc: dump-end
}

void module_dump() {
  // lief-doc: dump-runtime-start
  // Find the module to dump in the current process
  auto mod = LIEF::runtime::module_from_name("target.dll");

  // Dump the module's memory into a file (the raw bytes are also returned)
  std::vector<uint8_t> data = mod->dump("module.dump");

  auto pe = LIEF::PE::Parser::parse_from_dump("module.dump", mod->imagebase());
  // lief-doc: dump-runtime-end
  (void)data;
  (void)pe;
}

void advanced_parse_write() {
  // lief-doc: advanced-start
  LIEF::PE::ParserConfig parser_config;
  parser_config.parse_signature = false;

  auto pe = LIEF::PE::Parser::parse("some.exe", parser_config);

  LIEF::PE::Builder::config_t builder_config;
  builder_config.imports = true;

  pe->write("new.exe", builder_config);
  // lief-doc: advanced-end
}

void write_bytes() {
  // lief-doc: write-bytes-start
  std::unique_ptr<LIEF::PE::Binary> pe;

  std::ostringstream os;
  pe->write(os);
  std::string buffer = os.str();

  const auto* start = reinterpret_cast<const uint8_t*>(buffer.data());
  size_t size = buffer.size();
  // lief-doc: write-bytes-end
  (void)start;
  (void)size;
}

void authenticode() {
  // lief-doc: authenticode-start
  auto pe = LIEF::PE::Parser::parse("signed.exe");

  for (const LIEF::PE::Signature& sig : pe->signatures()) {
    for (const LIEF::PE::x509& crt : sig.certificates()) {
      std::cout << crt << '\n';
    }
  }

  std::cout << (pe->verify_signature() ==
                LIEF::PE::Signature::VERIFICATION_FLAGS::OK)
            << '\n';
  // lief-doc: authenticode-end
}

void parse_forms() {
  // lief-doc: parse-start

  // Using a file path as a std::string
  std::unique_ptr<LIEF::PE::Binary> pe = LIEF::PE::Parser::parse("some.exe");

  // Using a vector
  std::vector<uint8_t> my_raw_pe;
  pe = LIEF::PE::Parser::parse(my_raw_pe);
  // lief-doc: parse-end
}
