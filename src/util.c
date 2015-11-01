#include <stdlib.h>

#include "inc.h"

void *xmalloc(size_t sz)
{
	void *r = malloc(sz);

	if (!r)
		err(1, "malloc()");

	return r;
}

