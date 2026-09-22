#include <memory>

#include <LIEF/PE.hpp>

void create_export_entries() {
  // lief-doc: create-entries-start
  std::unique_ptr<LIEF::PE::Binary> pe;

  LIEF::PE::Export* exp = pe->get_export();

  // Remove an entry
  exp->remove_entry("my_exported_name");

  // Add a new export
  exp->add_entry("fuzz_me", 0x10010);

  LIEF::PE::Builder::config_t config;
  config.exports = true;
  config.export_section = ".myedata";

  pe->write("out.dll", config);
  // lief-doc: create-entries-end
}

void convert_to_dll() {
  // lief-doc: dll-header-start
  std::unique_ptr<LIEF::PE::Binary> pe;

  pe->header().add_characteristic(LIEF::PE::Header::CHARACTERISTICS::DLL);
  pe->optional_header().addressof_entrypoint(0);
  // lief-doc: dll-header-end
}

void create_export_table() {
  // lief-doc: create-table-start
  std::unique_ptr<LIEF::PE::Binary> pe;

  LIEF::PE::Export exp("lib_exe2dll.dll",
                       {
                           LIEF::PE::ExportEntry("cbk1", 0x0001000),
                           LIEF::PE::ExportEntry("cbk2", 0x0001010),
                       });

  pe->set_export(exp);

  LIEF::PE::Builder::config_t config;
  config.exports = true;

  pe->write("lib_exe2dll.dll", config);
  // lief-doc: create-table-end
}
