#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "ipsec.h"
#include "common_ipsec.h"

#if IPSEC_MEM_STATS
uint32_t allocated = 0;
#endif

void *ipsec_malloc(size_t size)
{	
	void *ptr = malloc(size);
	
	if (ptr == NULL) {
		PRINTF(IPSEC_ERROR "malloc() out of memory (%u bytes requested)\n", size);
		#if IPSEC_MEM_STATS
		allocated += size;
		PRINTF(IPSEC "IPsec now has %u B memory on the heap\n", allocated);
		#endif		
		return NULL;
	}
	PRINTF(IPSEC "Allocating %u bytes\n", size);
	return ptr;
}
