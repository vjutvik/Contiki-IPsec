/**
 * \addtogroup uip6
 * @{
 */
 
/**
  * \file
  *         This is an implementation of the Security Policy Database
  *         as described in RFC 4301, section 4.4.1.
  *
  */


/*---------------------------------------------------------------------------*/

#include "lib/list.h"
#include "spd.h"
#include "ipsec.h"
#include "common_ipsec.h"
#include "spd_conf.h"

/**
  * Return the SPD entry that applies to traffic of type \c addr
  *
  * \return the first entry (from the top) whose selector includes the address \c addr. NULL is returned if no such is found
  * (shouldn't happen because there *should* be a catch-all entry at the SPD's end).
  * 
  */
spd_entry_t *spd_get_entry_by_addr(ipsec_addr_t *addr) {
  uint8_t n;
  PRINTF("SPD lookup for traffic:\n");
  PRINTADDR(addr);
  for (n = 0; n < SPD_ENTRIES; ++n) {
    //PRINTF("\nSPD entry no. %u\n", n);
    //PRINTSPDENTRY(&spd_table[n]);
    if (ipsec_a_is_member_of_b(addr, (ipsec_addr_set_t *) &spd_table[n].selector)) {
      PRINTF("Found SPD entry:\n");
      PRINTSPDENTRY(&spd_table[n]);
      return &spd_table[n];
    }
  }
  PRINTF(IPSEC "Error: spd_get_entry_by_addr: Nothing found\n");
  return NULL;
}




/**
  * As above, but for traffic selectors (sets)
  */
/*
spd_entry_t spd_get_entry_by_ts(src_ts, dst_ts)
{
  spd_entry_t *entry;
  for (entry = list_head(spd); entry != NULL; entry = list_item_next(entry)) {
    if (ipsec_ts_is_subset_of_addr_set(addr, &entry->selector))
      return entry;
  }
  
  return NULL;  
}
*/


/** @} */
