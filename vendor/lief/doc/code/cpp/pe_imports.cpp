#include <cstdint>
#include <memory>
#include <string>

#include <LIEF/PE.hpp>

void remove_import() {
  // lief-doc: remove-import-start
  std::unique_ptr<LIEF::PE::Binary> pe;

  pe->remove_import("kernel32.dll");

  LIEF::PE::Builder::config_t config;
  config.imports = true;

  pe->write("new.exe", config);
  // lief-doc: remove-import-end
}

void remove_import_entry() {
  // lief-doc: remove-import-entry-start
  std::unique_ptr<LIEF::PE::Binary> pe;

  LIEF::PE::Import* kernel32 = pe->get_import("kernel32.dll");
  kernel32->remove_entry("IsDebuggerPresent");

  LIEF::PE::Builder::config_t config;
  config.imports = true;

  pe->write("new.exe", config);
  // lief-doc: remove-import-entry-end
}

void add_import() {
  // lief-doc: add-import-start
  std::unique_ptr<LIEF::PE::Binary> pe;

  LIEF::PE::Import& stdio = pe->add_import("api-ms-win-crt-stdio-l1-1-0.dll");
  LIEF::PE::ImportEntry& _puts = stdio.add_entry("puts");

  LIEF::PE::Builder::config_t config;
  config.imports = true;

  pe->write("new.exe", config);
  // lief-doc: add-import-end
  (void)_puts;
}

void add_import_cbk() {
  // lief-doc: add-import-cbk-start
  std::unique_ptr<LIEF::PE::Binary> pe;

  LIEF::PE::Import& stdio = pe->add_import("api-ms-win-crt-stdio-l1-1-0.dll");
  LIEF::PE::ImportEntry& _puts = stdio.add_entry("puts");

  LIEF::PE::Builder::config_t config;
  config.imports = true;
  config.resolved_iat_cbk = [](LIEF::PE::Binary* pe, const LIEF::PE::Import* imp,
                               const LIEF::PE::ImportEntry* entry,
                               uint32_t RVA) -> void {
    // Process
    return;
  };

  pe->write("new.exe", config);
  // lief-doc: add-import-cbk-end
  (void)_puts;
}

void add_import_func() {
  // lief-doc: add-import-func-start
  std::unique_ptr<LIEF::PE::Binary> pe;
  LIEF::PE::Import& kernel32 = pe->add_import("kernel32.dll");
  LIEF::PE::ImportEntry& _GetStartupInfoW = kernel32.add_entry("GetStartupInfoW");

  LIEF::PE::Builder::config_t config;
  config.imports = true;

  pe->write("new.exe", config);
  // lief-doc: add-import-func-end
}
