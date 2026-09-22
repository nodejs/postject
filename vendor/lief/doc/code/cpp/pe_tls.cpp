#include <cstdint>
#include <memory>
#include <utility>
#include <vector>

#include <LIEF/PE.hpp>

using namespace LIEF::PE;

void modify_callbacks() {
  // lief-doc: modify-callbacks-start
  std::unique_ptr<LIEF::PE::Binary> pe;

  TLS* tls = pe->tls();

  std::vector<uint64_t> callbacks = tls->callbacks();

  // Remove the last entry
  callbacks.pop_back();

  // Add an address
  callbacks.push_back(0x140001010);

  tls->callbacks(std::move(callbacks));

  pe->write("tls_modified.exe");
  // lief-doc: modify-callbacks-end
}

void create_tls() {
  // lief-doc: create-tls-start
  LIEF::PE::TLS tls;

  tls.callbacks(std::vector<uint64_t>{
      0x140001000,
      0x140001010,
  });
  // lief-doc: create-tls-end
  (void)tls;
}

void add_tls(std::unique_ptr<LIEF::PE::Binary>& pe) {
  LIEF::PE::TLS tls;
  // lief-doc: add-tls-start
  pe->tls(tls); // `tls` defined previously

  pe->write("tls_demo.exe");
  // lief-doc: add-tls-end
}
