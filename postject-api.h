// Copyright (c) 2022 Postman, Inc.

#include <cstddef>

#if defined(__APPLE__) && defined(__MACH__)
#include <mach-o/getsect.h>
#elif defined(__linux__)
#include <elf.h>
#elif defined(_WIN32)
#include <libloaderapi.h>
#endif

static constexpr const char* MACHO_DEFAULT_SEGMENT_NAME = "__POSTJECT";

struct MachOOptions {
  const char* framework_name = nullptr;
  const char* segment_name = MACHO_DEFAULT_SEGMENT_NAME;
};

// TODO
void* postject_find_resource(const char* name, size_t* size, MachOOptions* macho_options = nullptr) {
#if defined(__APPLE__) && defined(__MACH__)
  unsigned long section_size;
  char* ptr = nullptr;
  if (macho_options && macho_options->framework_name != nullptr) {
    ptr = getsectdatafromFramework(macho_options->framework_name, macho_options->segment_name, name, &section_size);
  } else {
    ptr = getsectdata(macho_options->segment_name, name, &section_size);
  }
  *size = static_cast<size_t>(section_size);

  return ptr;
#endif

  return nullptr;
}
