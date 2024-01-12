#ifndef POSTJECT_POSTJECT_HPP
#define POSTJECT_POSTJECT_HPP

#include <vector>
#include <string>

namespace postject {

enum class ExecutableFormat { kELF, kMachO, kPE, kUnknown };

enum class InjectResultType { kAlreadyExists, kError, kSuccess };
struct InjectResult {
  InjectResultType type;
  std::vector<uint8_t> output;
};

ExecutableFormat get_executable_format(const std::vector<uint8_t> &buffer);

InjectResult inject_into_elf(const std::vector<uint8_t> &executable,
                             const std::string &note_name,
                             const std::vector<uint8_t> &data,
                             bool overwrite = false);

InjectResult inject_into_macho(const std::vector<uint8_t>& executable,
                                         const std::string& segment_name,
                                         const std::string& section_name,
                                         const std::vector<uint8_t>& data,
                                         bool overwrite = false);

InjectResult inject_into_pe(const std::vector<uint8_t>& executable,
                                      const std::string& resource_name,
                                      const std::vector<uint8_t>& data,
                                      bool overwrite = false);
}

#endif // POSTJECT_POSTJECT_HPP
