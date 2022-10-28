#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "../dist/postject-api.h"

int main() {
  size_t size = 0;

  if (postject_has_resource() == true) {
    const void* ptr = postject_find_resource("foobar", &size, NULL);
    assert(ptr && size > 0);
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
    assert(ptr == NULL && size == 0);
    printf("Hello world\n");
  }

  return 0;
}
