#include <iostream>
#include <string>

#define POSTJECT_SENTINEL_FUSE "NODE_JS_FUSE_fce680ab2cc467b6e072b8b5df1996b2:0"
#include "../dist/postject-api.h"

int main() {
  size_t size = 0;

  if (postject_has_resource()) {
    const void* ptr = postject_find_resource("foobar", &size, nullptr);
    if (ptr == NULL) {
      std::cerr << "ptr must not be NULL." << std::endl;
      exit(1);
    }
    if (size == 0) {
      std::cerr << "size must not be 0." << std::endl;
      exit(1);
    }
    std::cout << std::string(static_cast<const char*>(ptr), size) << std::endl;
  } else {
    const void* ptr = postject_find_resource("foobar", &size, nullptr);
    if (ptr != nullptr) {
      std::cerr << "ptr must be nullptr." << std::endl;
      exit(1);
    }
    if (size > 0) {
      std::cerr << "size must not be greater than 0." << std::endl;
      exit(1);
    }
    std::cout << "Hello world" << std::endl;
  }

  return 0;
}
