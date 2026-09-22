#include <memory>

#include <LIEF/ELF.hpp>

using namespace LIEF::ELF;

void corefile_downcast(std::unique_ptr<LIEF::ELF::Binary>& binary) {
  // lief-doc: corefile-downcast-start
  for (const Note& note : binary->notes()) {
    if (CoreFile::classof(&note)) {
      const auto& nt_core_file = static_cast<const CoreFile&>(note);
    }
  }
  // lief-doc: corefile-downcast-end
}
