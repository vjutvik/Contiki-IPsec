/**
  * Implementation of the SAD (and the SPD-S cache) as described in RFC 4301.
  *
  */
#include <stdlib.h>
#include <lib/list.h>
#include <net/uip.h>
#include "sad.h"
#include "spd.h"


// Security Association Database
LIST(sad_incoming); // Invariant: The struct member spi is the primary key
LIST(sad_outgoing);


/**
  * Allocating SPI values for incoming traffic.
  *
  * We can match an incoming packet to the IPSec stack by using its SPI (given that we don't support NAT nor multicast,
  * which we don't). This is possible since we're the one assigning this value in the SAi2 payload of
  * the IKE exchange. next_sad_initiator_spi keeps track of the highest value we've assigned so far.
  */
static uint32_t next_sad_local_spi;


void sad_init()
{
  // Initialize the linked list
  list_init(sad_incoming);
  list_init(sad_outgoing);
  next_sad_local_spi = SAD_DYNAMIC_SPI_START;

  // I expect the compiler to inline this function as this is the
  // only point where it's called.
  sad_conf();
}


/**
  * Anti-replay: Assert that the sequence number fits in the window of this SA
  * and update it.
  */
uint8_t sad_incoming_replay(sad_entry_t *entry, uint32_t seqno)
{
  // Get offset to the highest registered sequence number
  // uint32_t offset = entry->seqno - seqno;

  PRINTF("SAD_INC_REPL: seqno %u spi %u\n", entry->seqno, entry->spi);

  if (seqno > entry->seqno) {
    // Highest sequence number observed. Window shifts to the right.
    entry->win = entry->win << (seqno - entry->seqno);
    entry->win = entry->win | 1U;
    entry->seqno = seqno;
  }
  else {
    // Sequence number is below the high end of the window
    uint32_t offset = entry->seqno - seqno;
    uint32_t mask = 1U << offset;
    if (offset > 31 || entry->win & mask)
      return 1; // The sequence number is outside the window or the window position is occupied

    entry->win |= mask;
  }
  
  return 0;
}

/**
  * Anti-replay: Get the sequence number for the next outgoing packet of this SA.
  */
/*
Not needed
uint32_t sad_get_seqno(sad_entry *entry)
{
  return ++entry->seqno;
}
*/

/*
sad_spds_key sad_hdr_to_spds_key(struct uip_ip_hdr *hdr) {
  sad_spds_key key;
  
  key.ip6_lsb_addr 
  key.layer4_src_port
  key.layer4_dst_port
  key.layer4_type
};
*/
//sad_spds_key sad_hdr_to_spds_key(struct uip_ip_hdr *hdr) {
//}


/**
  * Inserts an entry into the SAD for outgoing traffic.
  *
  * \param traffic_desc The type of traffic that can travel over the SA
  * \param spi SPI value
  * \param sa The SA's datastructure
  */
sad_entry_t *sad_create_outgoing_entry(uint32_t time_of_creation)
{
  sad_entry_t *newentry = malloc(sizeof(sad_entry_t));
  
  // Should we not assert that there's no traffic_desc overlap so that the invariant is upheld?

  // Insert the SPI in the right slot
  /*
  sad_entry_t *thisentry;
  for (thisentry = list_head(sad_outgoing);
    // The following condition should be simplified
    thisentry != NULL && !(thisentry->next == NULL || thisentry->next->spi >= spi); // >= because SPIs for outgoing SAs may be equal
    thisentry = thisentry->next) 
      ;
  list_insert(sad_outgoing, thisentry, newentry);
  */
  
  // Outgoing entry's SPI is usually decided by the other party
  SAD_RESET_ENTRY(newentry, time_of_creation);
  list_push(sad_outgoing, newentry);
  return newentry;
}


/**
  * Create a new SAD entry for incoming traffic, insert it into the incomming SAD and allocate a new SPI
  */
sad_entry_t *sad_create_incoming_entry(uint32_t time_of_creation)
{
  sad_entry_t *newentry = malloc(sizeof(sad_entry_t));

  SAD_RESET_ENTRY(newentry, time_of_creation);
  newentry->spi = uip_htonl(next_sad_local_spi++);
  list_push(sad_incoming, newentry);

  return newentry;
}


/**
  * Removes an entry from the SAD.
  *
  * \param entry Pointer to the entry
  */
/*
void sad_remove_outgoing_entry(sad_entry_t *entry)
{
  list_remove(sad, entry);
  free(entry);
}
*/

/**
  * SAD lookup by address for outgoing traffic.
  *
  * \param addr The address
  *
  * \return A pointer to the SAD entry whose \c traffic_desc address set includes the address of \c addr.
  * NULL is returned if there's no such match.
  *
  */
sad_entry_t *sad_get_outgoing(ipsec_addr_t *addr)
{
  sad_entry_t *entry;
  //PRINTF(IPSEC "sad_get_outgoing: finding SAD entry\n");
  //PRINTADDR(addr);
  for (entry = list_head(sad_outgoing); entry != NULL; entry = list_item_next(entry)) {    
    //PRINTSADENTRY(entry);    
    if (ipsec_a_is_member_of_b(addr, &entry->traffic_desc)) {
      PRINTF(IPSEC "sad_get_outgoing: found SAD entry with SPI %lx\n", uip_ntohl(entry->spi));
      return entry;
    }
  }
  return NULL;
}


/**
  * SAD lookup by SPI number for incoming traffic.
  *
  * \param spi The SPI number of the sought entry (in network byte order)
  *
  * \return A pointer to the SAD entry whose SPI match that of \c spi. NULL is returned if there's no such match.
  *
  */
sad_entry_t *sad_get_incoming(uint32_t spi)
{
  sad_entry_t *entry;
  for (entry = list_head(sad_incoming); entry != NULL; entry = list_item_next(entry)) {
    //PRINTF("==== SAD entry at %x ====\n  SPI no %lx\n", entry, uip_ntohl(spi));
    //PRINTSADENTRY(entry);
    if (entry->spi == spi)
      return entry;
  }
  PRINTF("SAD: No entry found\n");
  return NULL;
}

/**
  * Remove outgoing SAD entry (i.e. kill SA)
  */
void sad_remove_outgoing_entry(sad_entry_t *sad_entry)
{
  list_remove(sad_outgoing, sad_entry);
}

/**
  * Remove SAD entry (i.e. kill SA)
  */
void sad_remove_incoming_entry(sad_entry_t *sad_entry)
{
  list_remove(sad_incoming, sad_entry);
}

/**
  * Asserts that the address tag is a subset of the traffic pattern determined by sad_entry.
uint8_t sad_entry_fits_tag(ipsec_addr_t *tag, sad_entry_t *sad_entry);
*/
