#include <stdlib.h>
#include <string.h>

//#include "ike/payload.h"
#include "common_ipsec.h"

/**
  * DEBUG stuff
  */
void memprint(uint8_t *ptr, const uint16_t len)
{
  uint16_t r,s,t;
  for (r = 0; r < (len / 16) + 1; ++r) { // Row
    printf("%p (%4u) ", (uint8_t *) ptr + r * 16, r * 16);
    for (s = 0; s < 4; ++s) { // Group
      for (t = 0; t < 4; ++t)
        printf("%.2hx", ptr[r * 16 + s * 4 + t]);
      printf(" ");
    }
    printf("\n");
  }
}

uint8_t uip6_addr_a_is_in_closed_interval_bc(uip_ip6addr_t *a, uip_ip6addr_t *b, uip_ip6addr_t *c)
{
  return memcmp(a, b, sizeof(uip_ip6addr_t)) >= 0 && memcmp(a, c, sizeof(uip_ip6addr_t)) <= 0;  
}


/**
  * Compares an address and an adresses set and returns a value indicating whether or not \b a is a member of the set \b b.
  *
  * \return  1 if \b a is a \b member of \b b, 0 otherwise.
  */
uint8_t ipsec_a_is_member_of_b(ipsec_addr_t *a, ipsec_addr_set_t *b)
{
  return  uip6_addr_a_is_in_closed_interval_bc(a->peer_addr, b->peer_addr_from, b->peer_addr_to) && 
          a_is_in_closed_interval_bc(a->my_port, b->my_port_from, b->my_port_to) && 
          a_is_in_closed_interval_bc(a->peer_port, b->peer_port_from, b->peer_port_to) && 
          (b->nextlayer_proto == SPD_SELECTOR_NL_ANY_PROTOCOL || a->nextlayer_proto == b->nextlayer_proto);
}
