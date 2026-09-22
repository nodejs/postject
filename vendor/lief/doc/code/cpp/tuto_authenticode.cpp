#include <iostream>
#include <memory>

// lief-doc: ios-main-start
#include <LIEF/PE.hpp>

int main(int argc, char** argv) {
  std::unique_ptr<LIEF::PE::Binary> pe = LIEF::PE::Parser::parse(argv[1]);
  if (pe->verify_signature() == LIEF::PE::Signature::VERIFICATION_FLAGS::OK) {
    std::cout << "Signature ok!" << "\n";
    return 0;
  }
  std::cout << "Error!" << "\n";
  return 1;
}
// lief-doc: ios-main-end
