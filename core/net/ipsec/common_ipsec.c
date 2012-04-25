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

/**
  * DEBUG ends
  */

/**
  * Transforms an \c ipsec_addr_t to an \c ipsec_addr_set_t.
  *
  * \return addr_set
  */
/*
ipsec_addr_set_t *ipsec_addr_to_addr_set(ipsec_addr_set_t *addr_set, ipsec_addr_t *addr)
{
  addr_set->ip6addr_src_range_from = addr_set->ip6addr_src_range_to = addr->srcaddr;
  addr_set->ip6addr_dst_range_from = addr_set->ip6addr_dst_range_to = addr->dstaddr;

  addr_set->nextlayer_proto = addr->nextlayer_proto;
  
  addr_set->nextlayer_src_port_range_from = addr_set->nextlayer_src_port_range_to = addr->srcport;
  addr_set->nextlayer_dst_port_range_from = addr_set->nextlayer_dst_port_range_to = addr->dstport;  

  return addr_set;
}
*/

/**
  * Assert TS invariants
  */
/*
uint8_t ipsec_assert_ts_invariants(ike_ts_t *ts)
{
  return (uip6_addr_a_is_leq_than_b(ts->start_addr, ts->end_addr) &&
    ts->start_port <= ts->end_port);
}
*/

/*
uint8_t uip6_addr_a_is_geq_than_b(uip_ip6addr_t *a, uip_ip6addr_t *b)
{
  return memcmp(a, b, sizeof(uip_ip6addr_t)) >= 0;
}
*/

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




/**
  * Comparison betwen TS and selector.
  *
  * FIX: Broken
  */
/*
uint8_t ipsec_ts_is_subset_of_addr_set(ike_ts_t *ts_dst, ike_ts_t *ts_src, ipsec_addr_set_t *selector)
{
  return
    (selector->nextlayer_proto == SPD_SELECTOR_NL_ANY_PROTOCOL || selector->nextlayer_proto == ts->proto) &&
     uip6_addr_a_is_in_closed_interval_bc(&ts_src->start_addr, selector->ip6addr_src_range_from, selector->ip6addr_src_range_to) &&
     uip6_addr_a_is_in_closed_interval_bc(&ts_src->end_addr, selector->ip6addr_src_range_from, selector->ip6addr_src_range_to) &&
     uip6_addr_a_is_in_closed_interval_bc(&ts_dst->start_addr, selector->ip6addr_dst_range_from, selector->ip6addr_dst_range_to) &&
     uip6_addr_a_is_in_closed_interval_bc(&ts_dst->end_addr, selector->ip6addr_dst_range_from, selector->ip6addr_dst_range_to) &&
    
     a_is_in_closed_interval_bc(&ts_src->start_port, selector->nextlayer_src_port_range_from, selector->nextlayer_src_port_range_to) &&
     a_is_in_closed_interval_bc(&ts_src->end_port, selector->nextlayer_src_port_range_from, selector->nextlayer_src_port_range_to) &&
     a_is_in_closed_interval_bc(&ts_dst->start_port, selector->nextlayer_dst_port_range_from, selector->nextlayer_dst_port_range_to) &&
     a_is_in_closed_interval_bc(&ts_dst->end_port, selector->nextlayer_dst_port_range_from, selector->nextlayer_dst_port_range_to));
}
*/



/**
  * Compares two adresses spaces and returns a value indicating whether or no \b a is a subset of \b b
  *
  * \return  1 if \b a is a \b subset (sic! not a strict subset) of \b b, 0 otherwise.
  */
// uint8_t ipsec_a_is_subset_of_b(ipsec_addr_set_t *a, ipsec_addr_set_t *b)
// {
//   return 0;//ip6addr_src_range_from
// }
