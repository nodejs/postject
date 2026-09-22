#include <LIEF/LIEF.hpp>
#include <iostream>


void intro() {
  // lief-doc: intro-start
  std::unique_ptr<LIEF::MachO::FatBinary> fat =
      LIEF::MachO::Parser::parse("libobjc.dylib");

  for (const LIEF::MachO::Binary& macho : *fat) {
    for (const LIEF::MachO::BindingInfo& binding : macho.bindings()) {
      std::cout << binding.address() << ' ' << binding.symbol()->name() << '\n';
    }

    if (macho.is_ios()) {
      if (const LIEF::MachO::EncryptionInfo* info = macho.encryption_info()) {
        std::cout << info->crypt_id() << '\n';
      }
    }
  }
  // lief-doc: intro-end
}
