#include <memory>

#include <LIEF/PE.hpp>

void change_name() {
  // lief-doc: change-name-start
  std::unique_ptr<LIEF::PE::Binary> pe;

  pe->codeview_pdb()->filename(R"(C:\A\B\C\path.pdb)");

  pe->write("out.dll");
  // lief-doc: change-name-end
}

void remove() {
  // lief-doc: remove-start
  std::unique_ptr<LIEF::PE::Binary> pe;

  // Remove a single CodeViewPDB entry
  pe->remove_debug(*pe->codeview_pdb());

  // Remove all entries
  pe->clear_debug();

  pe->write("out.dll");
  // lief-doc: remove-end
}

void add() {
  // lief-doc: add-start
  std::unique_ptr<LIEF::PE::Binary> pe;

  LIEF::PE::CodeViewPDB cv("MyCustom.pdb");
  pe->add_debug_info(cv);

  pe->write("out.dll");
  // lief-doc: add-end
}
