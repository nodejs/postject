#include <LIEF/LIEF.hpp>

__attribute__((constructor)) void ctor() {
  LIEF::logging::err("In pid: " + std::to_string(LIEF::runtime::Process::pid()));
  for (const auto& M : LIEF::runtime::modules()) {
    LIEF::logging::err(M.to_string());
  }
}
