#include <LIEF/LIEF.hpp>
#include <windows.h>


BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
  LIEF::logging::err("In pid: " + std::to_string(LIEF::runtime::Process::pid()));
  for (const auto& M : LIEF::runtime::modules()) {
    LIEF::logging::err("  " + M.path());
  }
  return TRUE;
}
