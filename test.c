#include <stdio.h>
#include <string.h>

#include "postject-api.h"

#if defined(__linux__) && !defined(__POSTJECT_NO_SHT_PTR)
volatile void* _binary_postject_sht_start = (void*)POSTJECT_SHT_PTR_SENTINEL;
#endif

int main() {
  size_t size;
  void* ptr = postject_find_resource("foobar", &size, NULL);

  if (ptr && size > 0) {
    char* str = (char*)malloc(size + 1);
    memset(str, 0, size + 1);
    strncpy(str, ptr, size);
    printf("%s\n", str);
  } else {
    printf("Hello world\n");
  }

  return 0;
}
