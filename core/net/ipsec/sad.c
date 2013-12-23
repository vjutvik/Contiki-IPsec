/**
 * \addtogroup ipsec
 * @{
 */

/**
 * \file
 * 		The SAD and its interface
 * \author
 *		Vilhelm Jutvik <ville@imorgon.se>
 *
 */

/*
 * Copyright (c) 2012, Vilhelm Jutvik.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * This file is part of the Contiki operating system.
 */

/**
  * Implementation of the SAD (and the SPD-S cache) as described in RFC 4301.
  *
  */
#include <lib/list.h>
#include <net/uip.h>
#include "ipsec_malloc.h"
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
uint32_t next_sad_local_spi;


void sad_init()
{
  // Initialize the linked list
  list_init(sad_incoming);
  list_init(sad_outgoing);
  next_sad_local_spi = SAD_DYNAMIC_SPI_START;

  // I expect the compiler to inline this function as this is the
  // only point where it's called.
	#if WITH_CONF_MANUAL_SA
  sad_conf();
	#endif
}


/**
  * Anti-replay: Assert that the sequence number fits in the window of this SA
  * and update it.
  */
uint8_t sad_incoming_replay(sad_entry_t *entry, uint32_t seqno)
{
  // Get offset to the highest registered sequence number
  PRINTF("Incoming SA replay protection: seqno %u spi %x\n", entry->seqno, uip_ntohl(entry->spi));

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
    if (offset > 31 || entry->win & mask) {
      PRINTF(IPSEC "Error: Dropping packet because its sequence number is outside the reception window or it has been seen before (replay)\n");
      return 1; // The sequence number is outside the window or the window position is occupied
    }

    entry->win |= mask;
  }
  
  return 0;
}



/**
  * Inserts an entry into the SAD for outgoing traffic.
  *
  * \param time_of_creation Time of creation. A value of zero signifies that this is a manual SA.
  */
sad_entry_t *sad_create_outgoing_entry(uint32_t time_of_creation)
{
	PRINTF(IPSEC "Allocating memory for outgoing SA struct\n");
  sad_entry_t *newentry = ipsec_malloc(sizeof(sad_entry_t));

	if (newentry == NULL) {
		PRINTF(IPSEC_ERROR "Could not allocate memory for outgoing SA entry\n");
		return NULL;
	}
  
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
  *
  * \param time_of_creation Time of creation. A value of zero signifies that this is a manual SA.
  */
sad_entry_t *sad_create_incoming_entry(uint32_t time_of_creation)
{
	PRINTF(IPSEC "Allocating memory for incoming SA struct\n");
  sad_entry_t *newentry = ipsec_malloc(sizeof(sad_entry_t));

	if (newentry == NULL) {
		PRINTF(IPSEC_ERROR "Could not allocate memory for incoming SA entry\n");
		return NULL;
	}

  SAD_RESET_ENTRY(newentry, time_of_creation);
  newentry->spi = uip_htonl(next_sad_local_spi++);
  list_push(sad_incoming, newentry);

  return newentry;
}


/**
  * SAD lookup by address for outgoing traffic.
  *
  * \param addr The address
  *
  * \return A pointer to the SAD entry whose \c traffic_desc address set includes the address of \c addr.
  * NULL is returned if there's no such match.
  *
  */
sad_entry_t *sad_get_outgoing_entry(ipsec_addr_t *addr)
{
  sad_entry_t *entry;
  // PRINTF("In SAD_GET_OUTNING_ENtry. List head at %p\n", list_head(sad_outgoing));
  // PRINTF(IPSEC "sad_get_outgoing: finding SAD entry\nAddr:\n");
  // PRINTADDR(addr);
  // PRINTF(IPSEC "SPD-entry for addr===========\n");
  
  // FIX: The cross-check with the SPD is ugly. Move it to uip6.c or stop creating SAs that overlap SPD entries of different actions
  spd_entry_t *spd_entry = spd_get_entry_by_addr(addr);
  if (spd_entry->proc_action != SPD_ACTION_PROTECT)
    return NULL;
  //PRINTSPDENTRY(spd_entry);

  for (entry = list_head(sad_outgoing); entry != NULL; entry = list_item_next(entry)) {
    PRINTF("==== OUTGOING SAD entry at %p ====\n  SPI no %x\n", entry, uip_ntohl(entry->spi));
    PRINTSADENTRY(entry);    
    if (ipsec_a_is_member_of_b(addr, &entry->traffic_desc)) {
      PRINTF(IPSEC "sad_get_outgoing: found SAD entry with SPI %x\n", uip_ntohl(entry->spi));
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
sad_entry_t *sad_get_incoming_entry(uint32_t spi)
{
  sad_entry_t *entry;
  for (entry = list_head(sad_incoming); entry != NULL; entry = list_item_next(entry)) {
    PRINTF("==== INCOMING SAD entry at %p ====\n  SPI no %x\n", entry, uip_ntohl(spi));
    PRINTSADENTRY(entry);
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

/** @} */



