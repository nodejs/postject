#include <cstdint>
#include <iostream>
#include <memory>
#include <vector>

#include <LIEF/PE.hpp>
#include <LIEF/errors.hpp>

using namespace LIEF;
using namespace LIEF::PE;

void access_root() {
  // lief-doc: access-root-start
  std::unique_ptr<LIEF::PE::Binary> pe;

  LIEF::PE::ResourceNode* rsrc = pe->resources();

  std::cout << *rsrc << '\n';
  // lief-doc: access-root-end
}

void add_child() {
  // lief-doc: add-child-start
  std::unique_ptr<LIEF::PE::Binary> pe;

  LIEF::PE::ResourceNode* root = pe->resources();

  LIEF::PE::ResourceDirectory dir_node(/*id=*/100);
  LIEF::PE::ResourceData data_node(std::vector<uint8_t>{1, 2, 3});

  (*root).add_child(dir_node).add_child(data_node);

  pe->write("new.exe");
  // lief-doc: add-child-end
}

void set_manifest() {
  // lief-doc: manifest-start
  std::unique_ptr<LIEF::PE::Binary> pe;

  result<ResourcesManager> manager = pe->resources_manager();
  manager->manifest(R"manifest(
  <?xml version="1.0" standalone="yes"?>
  <assembly xmlns="urn:schemas-microsoft-com:asm.v1"
            manifestVersion="1.0">
    <trustInfo>
      <security>
        <requestedPrivileges>
           <requestedExecutionLevel level='asInvoker' uiAccess='false'/>
        </requestedPrivileges>
      </security>
    </trustInfo>
  </assembly>
  )manifest");

  pe->write("new.exe");
  // lief-doc: manifest-end
}

void transfer_resources() {
  // lief-doc: transfer-start
  std::unique_ptr<LIEF::PE::Binary> from;
  std::unique_ptr<LIEF::PE::Binary> to;

  to->set_resources(*from->resources());

  to->write("new.exe");
  // lief-doc: transfer-end
}
