#include <cassert>
#include <iostream>
#include <string>

#include "../dist/postject-api.h"

int main() {
  size_t size = 0;

  if (postject_has_resource() == true) {
    const void* ptr = postject_find_resource("foobar", &size, nullptr);
    assert(ptr && size > 0);
    std::cout << std::string(static_cast<const char*>(ptr), size) << std::endl;
  } else {
    const void* ptr = postject_find_resource("foobar", &size, nullptr);
    assert(ptr == nullptr && size == 0);
    std::cout << "Hello world" << std::endl;
  }

  return 0;
}
