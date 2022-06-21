#include <iostream>
#include <string>

#include "postject-api.h"

#if defined(__linux__) && !defined(__POSTJECT_NO_SHT_PTR)
volatile void* _binary_postject_sht_start = (void*)POSTJECT_SHT_PTR_SENTINEL;
#endif

int main() {
  size_t size;
  const void* ptr = postject_find_resource("foobar", &size, nullptr);

  if (ptr && size > 0) {
    std::cout << std::string(static_cast<const char*>(ptr), size) << std::endl;
  } else {
    std::cout << "Hello world" << std::endl;
  }

  return 0;
}
