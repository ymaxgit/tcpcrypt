#include <stdlib.h>
#include <err.h>

void *xmalloc(size_t sz)
{
	void *r = malloc(sz);

	if (!r)
		err(1, "malloc()");

	return r;
}

