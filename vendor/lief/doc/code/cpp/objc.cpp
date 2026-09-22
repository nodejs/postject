#include <iostream>
#include <memory>

#include <LIEF/MachO.hpp>
#include <LIEF/ObjC.hpp>

void check() {
  // lief-doc: check-start
  std::unique_ptr<LIEF::MachO::Binary> macho;

  std::unique_ptr<LIEF::objc::Metadata> metadata = macho->objc_metadata();

  if (metadata != nullptr) {
    std::cout << "Objective metadata found\n";
  }
  // lief-doc: check-end
}

void inspect() {
  // lief-doc: inspect-start
  std::unique_ptr<LIEF::MachO::Binary> bin;

  std::unique_ptr<LIEF::objc::Metadata> metadata = bin->objc_metadata();

  for (const LIEF::objc::Class& clazz : metadata->classes()) {
    std::cout << "name=" << clazz.name() << '\n';
    for (const LIEF::objc::Method& meth : clazz.methods()) {
      std::cout << "  method.name=" << meth.name() << '\n';
    }
  }

  std::cout << metadata->to_decl();
  // lief-doc: inspect-end
}
