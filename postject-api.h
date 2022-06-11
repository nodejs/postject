// Copyright (c) 2022 Postman, Inc.

#ifndef POSTJECT_API_H_
#define POSTJECT_API_H_

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#if defined(__APPLE__) && defined(__MACH__)
#include <mach-o/getsect.h>
#elif defined(__linux__)
#include <elf.h>
#elif defined(_WIN32)
#include <windows.h>
#endif

struct PostjectOptions {
  const char* elf_section_name;
  const char* macho_framework_name;
  const char* macho_section_name;
  const char* macho_segment_name;
  const char* pe_resource_name;
};

static void postject_options_init(struct PostjectOptions* options) {
  options->elf_section_name = NULL;
  options->macho_framework_name = NULL;
  options->macho_section_name = NULL;
  options->macho_segment_name = NULL;
  options->pe_resource_name = NULL;
}

static void* postject_find_resource(const char* name,
                                    size_t* size,
                                    const struct PostjectOptions* options) {
#if defined(__APPLE__) && defined(__MACH__)
  char* section_name = NULL;
  const char* segment_name = "__POSTJECT";

  if (options != NULL && options->macho_segment_name != NULL) {
    segment_name = options->macho_segment_name;
  }

  if (options != NULL && options->macho_section_name != NULL) {
    name = options->macho_section_name;
  } else if (strncmp(name, "__", 2) != 0) {
    // Automatically prepend __ to match naming convention
    section_name = (char*)malloc(strlen(name) + 2);
    strcpy(section_name, "__");
    strcat(section_name, name);
  }

  unsigned long section_size;
  char* ptr = NULL;
  if (options != NULL && options->macho_framework_name != NULL) {
    ptr = getsectdatafromFramework(options->macho_framework_name, segment_name,
                                   section_name != NULL ? section_name : name,
                                   &section_size);
  } else {
    ptr = getsectdata(segment_name, section_name != NULL ? section_name : name,
                      &section_size);
  }

  if (section_name != NULL) {
    free(section_name);
  }

  if (size != NULL) {
    *size = (size_t)section_size;
  }

  return ptr;
#elif defined(__linux__)
  // TODO - Implement for ELF
#elif defined(_WIN32)
  if (options != NULL && options->pe_resource_name != NULL) {
    name = options->pe_resource_name;
  }

  HRSRC resource_handle =
      FindResourceA(NULL, name, MAKEINTRESOURCEA(10) /* RT_RCDATA */);

  if (resource_handle) {
    HGLOBAL global_resource_handle = LoadResource(NULL, resource_handle);

    if (global_resource_handle) {
      if (size != NULL) {
        *size = SizeofResource(NULL, resource_handle);
      }

      return LockResource(global_resource_handle);
    }
  }
#endif

  if (size != NULL) {
    *size = 0;
  }

  return NULL;
}

#endif  // POSTJECT_API_H_
