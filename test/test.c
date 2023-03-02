#define _GNU_SOURCE  // This is needed because postject-api.h uses
                     // dl_iterate_phdr and dl_phdr_info which are non-standard
                     // GNU extensions.

#include <stdio.h>
#include <string.h>

#include "../dist/postject-api.h"

int main() {
  size_t size = 0;

  if (postject_has_resource()) {
    const void* ptr = postject_find_resource("foobar", &size, NULL);
    if (ptr == NULL) {
      fprintf(stderr, "ptr must not be NULL.\n");
      exit(1);
    }
    if (size == 0) {
      fprintf(stderr, "size must not be 0.\n");
      exit(1);
    }
    char* str = (char*)malloc(size + 1);
    memset(str, 0, size + 1);
#if defined(_WIN32)
    strncpy_s(str, size + 1, ptr, size);
#else
    strncpy(str, ptr, size);
#endif
    printf("%s\n", str);
  } else {
    const void* ptr = postject_find_resource("foobar", &size, NULL);
    if (ptr != NULL) {
      fprintf(stderr, "ptr must be NULL.\n");
      exit(1);
    }
    if (size > 0) {
      fprintf(stderr, "size must not be greater than 0.\n");
      exit(1);
    }
    printf("Hello world\n");
  }

  return 0;
}
