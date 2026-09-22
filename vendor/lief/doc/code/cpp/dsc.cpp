#include <iostream>
#include <memory>

#include <LIEF/DyldSharedCache.hpp>
#include <LIEF/MachO.hpp>

using namespace LIEF::dsc;

void iterate_libraries() {
  // lief-doc: libraries-start
  std::unique_ptr<LIEF::dsc::DyldSharedCache> dyld_cache;

  for (const LIEF::dsc::Dylib& dylib : dyld_cache->libraries()) {
    std::cout << dylib.address() << ' ' << dylib.path() << '\n';
  }
  // lief-doc: libraries-end
}

void extract() {
  // lief-doc: extract-start
  std::unique_ptr<LIEF::dsc::DyldSharedCache> dyld_cache;

  std::unique_ptr<Dylib> liblockdown =
      dyld_cache->find_lib_from_name("liblockdown.dylib");

  std::unique_ptr<LIEF::MachO::Binary> macho = liblockdown->get();
  for (const LIEF::MachO::SegmentCommand& segment : macho->segments()) {
    std::cout << segment.name() << '\n';
  }
  // lief-doc: extract-end
}

void write_back() {
  // lief-doc: write-start
  std::unique_ptr<LIEF::dsc::DyldSharedCache> dyld_cache;

  std::unique_ptr<Dylib> liblockdown =
      dyld_cache->find_lib_from_name("liblockdown.dylib");

  std::unique_ptr<LIEF::MachO::Binary> macho = liblockdown->get();
  macho->write("on-disk-liblockdown.dylib");
  // lief-doc: write-end
}

void random_access() {
  // lief-doc: random-access-start
  std::unique_ptr<LIEF::dsc::DyldSharedCache> dyld_cache;

  // No cost
  auto libraries = dyld_cache->libraries();

  // O(1) cost: the iterator is random access, so an arbitrary library can be
  // reached by index without materializing the ones before it.
  std::cout << "First library: " << libraries[0]->path() << '\n';

  // O(libraries.size()) cost
  for (const Dylib& dylib : libraries) {
    std::cout << dylib.path() << '\n';
  }
  // lief-doc: random-access-end
}

void load() {
  // lief-doc: load-start
  std::unique_ptr<LIEF::dsc::DyldSharedCache> dyld_cache =
      LIEF::dsc::load("macos-15.0.1/");
  // lief-doc: load-end
  (void)dyld_cache;
}
