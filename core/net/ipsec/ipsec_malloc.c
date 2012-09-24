#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "ipsec.h"
#include "common_ipsec.h"

void *ipsec_malloc(size_t size)
{	
	void *ptr = malloc(size);
	
	if (ptr == NULL) {
		PRINTF(IPSEC_ERROR "malloc() out of memory (%u bytes requested)\n", size);
		return NULL;
	}
	PRINTF(IPSEC "Allocating %u bytes\n", size);
	return ptr;
}
