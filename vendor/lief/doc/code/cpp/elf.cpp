#include <cassert>
#include <cstdint>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include <LIEF/ELF.hpp>
#include <LIEF/runtime.hpp>

using namespace LIEF::ELF;

void inspect() {
  // lief-doc: inspect-start
  std::unique_ptr<LIEF::ELF::Binary> elf;

  std::cout << elf->header().entrypoint();

  for (const LIEF::ELF::Section& section : elf->sections()) {
    std::cout << section.name() << section.content().size() << '\n';
  }
  // lief-doc: inspect-end
}

void modify_write() {
  // lief-doc: write-start
  std::unique_ptr<LIEF::ELF::Binary> elf;

  elf->add_library("libdemo.so");
  elf->write("new.elf");
  // lief-doc: write-end
}

void write_bytes() {
  // lief-doc: write-bytes-start
  std::unique_ptr<LIEF::ELF::Binary> elf;

  std::ostringstream os;
  elf->write(os);
  std::string buffer = os.str();

  const auto* start = reinterpret_cast<const uint8_t*>(buffer.data());
  size_t size = buffer.size();
  // lief-doc: write-bytes-end
  (void)start;
  (void)size;
}

void add_loaded_segment() {
  // lief-doc: add-segment-start
  std::unique_ptr<LIEF::ELF::Binary> elf;

  LIEF::ELF::Segment segment;
  segment.type(LIEF::ELF::Segment::TYPE::LOAD);
  segment.content({1, 2, 3});

  LIEF::ELF::Segment* new_segment = elf->add(segment);
  elf->write("new.elf");
  // lief-doc: add-segment-end
  (void)new_segment;
}

void add_loaded_section() {
  // lief-doc: add-section-loaded-start
  std::unique_ptr<LIEF::ELF::Binary> elf;

  LIEF::ELF::Section section(".lief_demo");
  section.content({1, 2, 3});

  LIEF::ELF::Section* new_section = elf->add(section, /*loaded=*/true);
  elf->write("new.elf");
  // lief-doc: add-section-loaded-end
  (void)new_section;
}

void add_unloaded_section() {
  // lief-doc: add-section-unloaded-start
  std::unique_ptr<LIEF::ELF::Binary> elf;

  LIEF::ELF::Section section(".metadata");
  section.content({1, 2, 3});

  LIEF::ELF::Section* new_section = elf->add(section, /*loaded=*/false);
  elf->write("new.elf");
  // lief-doc: add-section-unloaded-end
  (void)new_section;
}

void parse_from_dump() {
  // lief-doc: dump-start
  auto elf = LIEF::ELF::Parser::parse_from_dump("module.dump", 0x7f9b98e00000);

  for (const LIEF::ELF::Segment& segment : elf->segments()) {
    std::cout << to_string(segment.type()) << '\n';
  }
  // lief-doc: dump-end
}

void module_dump() {
  // lief-doc: dump-runtime-start
  // Find the module to dump in the current process
  auto mod = LIEF::runtime::module_from_name("libc.so.6");

  // Dump the module's memory into a file (the raw bytes are also returned)
  std::vector<uint8_t> data = mod->dump("module.dump");

  auto elf = LIEF::ELF::Parser::parse_from_dump("module.dump", mod->imagebase());
  // lief-doc: dump-runtime-end
  (void)data;
  (void)elf;
}

void advanced_parse_write() {
  // lief-doc: advanced-start
  LIEF::ELF::ParserConfig parser_config;
  parser_config.parse_overlay = false;

  auto elf = LIEF::ELF::Parser::parse("my.elf", parser_config);

  LIEF::ELF::Builder::config_t builder_config;
  builder_config.gnu_hash = false;

  elf->write("new.elf", builder_config);
  // lief-doc: advanced-end
}

void rpath_add() {
  // lief-doc: rpath-add-start
  std::unique_ptr<LIEF::ELF::Binary> elf;

  LIEF::ELF::DynamicEntryRunPath runpath("$ORIGIN:/opt/lib64");

  elf->add(runpath);

  LIEF::ELF::DynamicEntryRunPath other_runpath(
      std::vector<std::string>{"$ORIGIN", "/opt/lib64"}
  );

  elf->add(other_runpath);

  elf->write("updated.elf");
  // lief-doc: rpath-add-end
}

void rpath_change() {
  // lief-doc: rpath-change-start
  std::unique_ptr<LIEF::ELF::Binary> elf;

  auto* runpath = elf->get(LIEF::ELF::DynamicEntry::TAG::RUNPATH)
                      ->cast<LIEF::ELF::DynamicEntryRunPath>();

  assert(runpath != nullptr);

  runpath->runpath("$ORIGIN:/opt/lib64");
  runpath->append("lib-x86_64-gnu");

  elf->write("updated.elf");
  // lief-doc: rpath-change-end
}

void rpath_remove() {
  // lief-doc: rpath-remove-start
  std::unique_ptr<LIEF::ELF::Binary> elf;

  // Remove **all** DT_RUNPATH entries
  elf->remove(LIEF::ELF::DynamicEntry::TAG::RUNPATH);

  // Remove all entries that contain '$ORIGIN'
  std::vector<LIEF::ELF::DynamicEntryRunPath*> to_remove;
  for (DynamicEntry& entry : elf->dynamic_entries()) {
    if (auto* dt_entry = entry.cast<LIEF::ELF::DynamicEntryRunPath>()) {
      if (dt_entry->runpath().find("$ORIGIN") != std::string::npos) {
        to_remove.push_back(dt_entry);
      }
    }
  }

  for (LIEF::ELF::DynamicEntryRunPath* entry : to_remove) {
    elf->remove(*entry);
  }

  elf->write("updated.elf");
  // lief-doc: rpath-remove-end
}

void symver_remove_symbol() {
  // lief-doc: symver-symbol-start
  std::unique_ptr<LIEF::ELF::Binary> elf;

  LIEF::ELF::Symbol* sym = elf->get_dynamic_symbol("printf");

  assert(sym != nullptr);

  sym->symbol_version()->as_global();

  elf->write("updated.elf");
  // lief-doc: symver-symbol-end
}

void symver_remove_library() {
  // lief-doc: symver-library-start
  std::unique_ptr<LIEF::ELF::Binary> elf;

  elf->remove_version_requirement("libm.so.6");

  elf->write("updated.elf");
  // lief-doc: symver-library-end
}

void parse_forms() {
  // lief-doc: parse-start

  // Using a file path as a std::string
  std::unique_ptr<LIEF::ELF::Binary> elf = LIEF::ELF::Parser::parse("/bin/ls");

  // Using a vector
  std::vector<uint8_t> my_raw_elf;
  elf = LIEF::ELF::Parser::parse(my_raw_elf);
  // lief-doc: parse-end
}
