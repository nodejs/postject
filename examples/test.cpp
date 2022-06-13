#include <iostream>
#include <string>

#include "../postject-api.h"

int main()
{
	size_t size;
	const void *ptr = postject_find_resource("foobar", &size, nullptr);

	if (ptr && size > 0) {
		std::cout << std::string(static_cast<const char *>(ptr), size)
			  << std::endl;
	} else {
		std::cout << "Hello world" << std::endl;
	}

	return 0;
}
