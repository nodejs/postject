#include <assert.h>
#include <stdio.h>

#include "../../postject-api.h"

int main()
{
  size_t size;
  const void *ptr = postject_find_resource("foobar", &size, NULL);

  assert(ptr != NULL);
  assert(size > 0);

  fwrite(ptr, size, 1, stdout);

  return 0;
}
