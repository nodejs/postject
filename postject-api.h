// Copyright (c) 2022 Postman, Inc.

#ifndef POSTJECT_API_H_
#define POSTJECT_API_H_

#include <stddef.h>

#if defined(__APPLE__) && defined(__MACH__)
#include <mach-o/getsect.h>
#elif defined(__linux__)
#include <elf.h>
#elif defined(_WIN32)
#include <windows.h>
#endif

struct MachOOptions {
  const char* framework_name;
  const char* segment_name;
};

void postject_macho_options_init(struct MachOOptions* options) {
  options->framework_name = NULL;
  options->segment_name = NULL;
}

void* postject_find_resource(const char* name, size_t* size, const struct MachOOptions* macho_options) {
#if defined(__APPLE__) && defined(__MACH__)
  const char* segment_name = "__POSTJECT";

  if (macho_options && macho_options->segment_name != NULL) {
    segment_name = macho_options->segment_name;
  }

  unsigned long section_size;
  char* ptr = NULL;
  if (macho_options && macho_options->framework_name != NULL) {
    ptr = getsectdatafromFramework(macho_options->framework_name, segment_name, name, &section_size);
  } else {
    ptr = getsectdata(segment_name, name, &section_size);
  }

  *size = (size_t) section_size;
  return ptr;
#elif defined(__linux__)
  // TODO - Implement for ELF
#elif defined(_WIN32)
  HRSRC resource_handle = FindResourceA(NULL, name, MAKEINTRESOURCEA(10) /* RT_RCDATA */);

  if (resource_handle) {
    HGLOBAL global_resource_handle = LoadResource(NULL, resource_handle);

    if (global_resource_handle) {
      *size = SizeofResource(NULL, resource_handle);
      return LockResource(global_resource_handle);
    }
  }
#endif

  *size = 0;
  return NULL;
}

#endif  // POSTJECT_API_H_
