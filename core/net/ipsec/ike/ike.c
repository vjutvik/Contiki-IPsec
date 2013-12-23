/**
 * \addtogroup ipsec
 * @{
 */

/**
 * \file
 * 		Main IKEv2 functions
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

#include "machine.h"
#include "ike.h"
#include "common_ipsec.h"
#include "common_ike.h"
#include "spd.h"

#if IPSEC_TIME_STATS
#include <clock.h>
#endif

ipsec_addr_t ike_arg_packet_tag;
process_event_t ike_negotiate_event;

/**
	* Functions for (roughly) finding the stack's maximum extent.
	*
	* cover() 							covers STACK_MAX_MEM B of stack memory with the character 'h'
	* get_cover_consumed() 	counts the number of bytes from the current stack
	*												offset to the beginning of the area covered by 'h'
	*/
#if IPSEC_MEM_STATS
#define STACK_MAX_MEM 2000

void dummy(u8_t *ptr) {};

u8_t *cover(void)
{
	volatile u8_t buff[STACK_MAX_MEM];
	u16_t i;
	for (i = 0; i < STACK_MAX_MEM; ++i)
		buff[i] = 'h';
		
	return (u8_t *) buff;
}

u16_t get_cover_consumed(u8_t *buff)
{
	u16_t i;
	for (i = STACK_MAX_MEM - 5; i > 4 && strncmp((const char *) (buff + i), "hhhhh", 5); --i)
		;
	return i;
}
#endif


void ike_init()
{
  ecc_init();
  
  ike_negotiate_event = process_alloc_event();
  process_start(&ike2_service, NULL);
}


static void ike_negotiate_sa(ipsec_addr_t *triggering_pkt_addr, spd_entry_t *commanding_entry)
{
  /**
    * We're here because the outgoing packet associated with trigger_pkt_addr didn't find any SAD entry
    * with matching traffic selectors. The expected result of a call to this function is that the Child SA
    * is negotiated with the other peer and inserted into the SAD. Until that happens, traffic of this type 
    * is simply dropped.
    *
    * Search the session table for an IKE session where the remote peer's IP matches that of the triggering
    * packet's. If such is found, start at state 
    * ike_statem_state_common_createchildsa(session, addr_t triggering_pkt, spd_entry_t commanding_entry)
    * if busy, discard pkt
    *
    */

	/**
		* Code for identifying and using an existing session still to be implemented
		*/
  /**
  ike_statem_session_t *session;
  if((session = ike_statem_get_session_by_addr(triggering_pkt_addr->addr)) != NULL) {
    // Command this session to create a new child SA
    if (IKE_STATEM_SESSION_ISREADY(session)) {
      PRINTF(IPSEC_IKE "Using existing IKE session for SA negotiation\n");
//      **
        * Cause the already established session to negotiate a new set of SAs. Disabled as for now.
//        *
      // Warn: Second negotiation attempt. Disabled
    }
    else
      PRINTF(IPSEC_IKE ": Warning: Couldn't create child SA in response to triggering packet since IKE session was busy\n");
  }
  else {*/
    // We don't have an IKE session with this host. Connect and setup.
    ike_statem_setup_initiator_session(triggering_pkt_addr, commanding_entry);
  //}
}


/**
  * IKEv2 protothread. Handles the events by which the service is controlled.
  *
  EVENTS
  
    TYPE: ike_negotiate_event
    DESCRIPTION: Initiates an IKEv2 negotiation with the destination host. Data points to SPD entry that required the
                packet to be protected. The address of the triggering packet must be stored in ike_arg_packet_tag
  
    TYPE: tcpip_event
    DESCRIPTION: Dispatched by the uIP stack upon reception of new data. Data is undefined.
    
    (More to come? SAD operations likely)
  *
  */
PROCESS(ike2_service, "IKEv2 Service");
PROCESS_THREAD(ike2_service, ev, data)
{
  PROCESS_BEGIN();
  
  ike_statem_init();
  
  while(1) {
    PROCESS_WAIT_EVENT();


		#if IPSEC_MEM_STATS
		u8_t *stackbuff = cover();
		#endif

 		#if IPSEC_TIME_STATS
		clock_time_t start = clock_time();
 /*
 		ENERGEST_TYPE_CPU,
 	  ENERGEST_TYPE_LPM,
 	  ENERGEST_TYPE_IRQ,
 	  ENERGEST_TYPE_LED_GREEN,
 	  ENERGEST_TYPE_LED_YELLOW,
 	  ENERGEST_TYPE_LED_RED,
 	  ENERGEST_TYPE_TRANSMIT,
 	  ENERGEST_TYPE_LISTEN,
 	*/
 		#endif

 
    if (ev == ike_negotiate_event) {
      PRINTF(IPSEC_IKE "Negotiating child SAs in response to SPD entry %p for triggering packet\n", data);
      
      ike_negotiate_sa(&ike_arg_packet_tag, (spd_entry_t *) data);
    }
    else {
      if (ev == tcpip_event)
        ike_statem_incoming_data_handler();
      else
        PRINTF(IPSEC_IKE "IKEv2 Service: Unknown event\n");
    }

		#if IPSEC_TIME_STATS
		clock_time_t elapsed = clock_time() - start;
		u16_t sec = elapsed / CLOCK_SECOND;
		u16_t parts = elapsed % CLOCK_SECOND;
		u16_t clock_second = CLOCK_SECOND;
		PRINTF(IPSEC_IKE "Time required %u sec, %u parts (CLOCK_SECOND is %u)\n", sec, parts, clock_second);
		#endif

		#if IPSEC_MEM_STATS
		PRINTF(IPSEC_IKE "Stack extended, at most, to %u B	\n", get_cover_consumed(stackbuff));
		#endif
		
		
  }
  
  PROCESS_END();
}

/** @} */