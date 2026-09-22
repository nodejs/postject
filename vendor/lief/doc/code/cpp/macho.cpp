#include <cstdint>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include <LIEF/MachO.hpp>
#include <LIEF/runtime.hpp>

using namespace LIEF::MachO;

void iterate() {
  // lief-doc: iterate-start
  std::unique_ptr<LIEF::MachO::FatBinary> fat;

  // Iterate
  for (const LIEF::MachO::Binary& macho : *fat) {
    std::cout << macho.entrypoint() << '\n';
    std::cout << macho.commands().size() << '\n';
  }

  // Pick one at the specified index (without taking ownership)
  const LIEF::MachO::Binary* macho = fat->at(0);

  // Pick one at the specified index and taking ownership
  std::unique_ptr<LIEF::MachO::Binary> owned = fat->take(0);

  // Pick one with the given arch and taking ownership
  std::unique_ptr<LIEF::MachO::Binary> arm64 =
      fat->take(LIEF::MachO::Header::CPU_TYPE::ARM64);
  // lief-doc: iterate-end
  (void)macho;
  (void)owned;
  (void)arm64;
}

void write_bytes() {
  // lief-doc: write-bytes-start
  std::unique_ptr<LIEF::MachO::Binary> macho;

  std::ostringstream os;
  macho->write(os);
  std::string buffer = os.str();

  const auto* start = reinterpret_cast<const uint8_t*>(buffer.data());
  size_t size = buffer.size();
  // lief-doc: write-bytes-end
  (void)start;
  (void)size;
}

void parse_from_dump() {
  // lief-doc: dump-start
  auto fat = LIEF::MachO::Parser::parse_from_dump("module.dump", 0x11e32c000);
  const LIEF::MachO::Binary* macho = fat->at(0);

  for (const LIEF::MachO::SegmentCommand& segment : macho->segments()) {
    std::cout << segment.name() << '\n';
  }
  // lief-doc: dump-end
}

void module_dump() {
  // lief-doc: dump-runtime-start
  // Find the module to dump in the current process
  auto mod = LIEF::runtime::module_from_name("libsystem_c.dylib");

  // Dump the module's memory into a file (the raw bytes are also returned)
  std::vector<uint8_t> data = mod->dump("module.dump");

  auto fat = LIEF::MachO::Parser::parse_from_dump("module.dump", mod->imagebase());
  // lief-doc: dump-runtime-end
  (void)data;
  (void)fat;
}

void rpath_change_lib() {
  // lief-doc: rpath-change-lib-start
  std::unique_ptr<LIEF::MachO::Binary> macho =
      LIEF::MachO::Parser::parse("hello.bin")->take(0);

  LIEF::MachO::DylibCommand* lib = macho->find_library("libmylib.dylib");
  lib->name("/opt/homebrew/my_package/libmylib.dylib");

  macho->write("hello_fixed.bin");
  // lief-doc: rpath-change-lib-end
}

void rpath_add() {
  // lief-doc: rpath-add-start
  std::unique_ptr<LIEF::MachO::Binary> macho =
      LIEF::MachO::Parser::parse("hello.bin")->take(0);

  auto rpath = LIEF::MachO::RPathCommand::create("/opt/homebrew/my_package");
  macho->add(*rpath);
  // lief-doc: rpath-add-end
}

void rpath_atrpath() {
  // lief-doc: rpath-atrpath-start
  std::unique_ptr<LIEF::MachO::Binary> macho;

  LIEF::MachO::DylibCommand* lib = macho->find_library("libmylib.dylib");
  lib->name("@rpath/libmylib.dylib");

  macho->write("hello_fixed.bin");
  // lief-doc: rpath-atrpath-end
}

void parse_forms() {
  // lief-doc: parse-start

  // Using a file path as a std::string
  std::unique_ptr<LIEF::MachO::FatBinary> macho =
      LIEF::MachO::Parser::parse("/bin/ls");

  // Using a vector
  std::vector<uint8_t> my_raw_macho;
  macho = LIEF::MachO::Parser::parse(my_raw_macho);
  // lief-doc: parse-end
}

void write_fat() {
  // lief-doc: write-fat-start
  std::unique_ptr<LIEF::MachO::FatBinary> macho;

  macho->take(LIEF::MachO::Header::CPU_TYPE::ARM64)->write("fit.macho");
  macho->write("fat.macho");
  // lief-doc: write-fat-end
}

void advanced_parse_write() {
  // lief-doc: advanced-start
  LIEF::MachO::ParserConfig parser_config;
  parser_config.parse_dyld_bindings = false;

  std::unique_ptr<LIEF::MachO::FatBinary> fat =
      LIEF::MachO::Parser::parse("my.macho", parser_config);

  LIEF::MachO::Binary* macho = fat->at(0);

  LIEF::MachO::Builder::config_t builder_config;
  builder_config.linkedit = false;

  macho->write("new.macho", builder_config);
  // lief-doc: advanced-end
}
