#ifndef __FILTER_H__
#define __FILTER_H__

#include "sad.h"
#include "spd.h"

uint8_t ipsec_filter(sad_entry_t *sad_entry, ipsec_addr_t *tag);

#endif
