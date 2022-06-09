// Copyright (c) 2022 Postman, Inc.

#ifndef POSTJECT_API_H_
#define POSTJECT_API_H_

#include <stddef.h>

#if defined(__APPLE__) && defined(__MACH__)
#include <mach-o/getsect.h>
#elif defined(__linux__)
#include <elf.h>
#elif defined(_WIN32)
#include <libloaderapi.h>
#include <winbase.h>
#endif

struct MachOOptions {
  const char* framework_name;
  const char* segment_name;
};

void postject_macho_options_init(MachOOptions* options) {
  options->framework_name = nullptr;
  options->segment_name = nullptr;
}

void* postject_find_resource(const char* name, size_t* size, const MachOOptions* macho_options = nullptr) {
#if defined(__APPLE__) && defined(__MACH__)
  unsigned long section_size;
  char* ptr = nullptr;
  if (macho_options && macho_options->framework_name != nullptr) {
    ptr = getsectdatafromFramework(macho_options->framework_name, macho_options->segment_name, name, &section_size);
  } else {
    const char* segment_name = "__POSTJECT";

    if (macho_options && macho_options->segment_name != nullptr) {
      segment_name = macho_options->segment_name;
    }

    ptr = getsectdata(segment_name, name, &section_size);
  }
  *size = static_cast<size_t>(section_size);

  return ptr;
#elif defined(__linux__)
  // TODO - Implement for ELF
#elif defined(_WIN32)
  HRSRC resource_handle = FindResourceA(nullptr, resource_name, RT_RCDATA);

  if (resource_handle != nullptr) {
    *size = SizeofResource(nullptr, resource_handle);
    return LockResource(LoadResource(nullptr, resource_handle));
  }
#endif

  *size = 0;
  return nullptr;
}

#endif  // POSTJECT_API_H_
