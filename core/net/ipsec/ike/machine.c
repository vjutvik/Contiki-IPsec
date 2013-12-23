/**
 * \addtogroup ipsec
 * @{
 */

/**
 * \file
 * 		Helper functions for the state machines
 * \details
 * 		Definitions for the Mealy State Machine implementing the behavior of IKEv2.
 * 		Everything in this file pertains to RFC 5996 (hereafter referred to as "the RFC").
 * 		
 * 		The machine is designed for memory efficiency, translating into an emphasis of code
 * 		reuse and small memory buffers. 
 * 		
 * 		Code reuse is improved by only placing state transition code into the states. Transition-specific 
 * 		code with side effects and message generation are placed in the edges' functions 
 * 		(which can be reused over multiple different transitions).
 * 		
 * 		As for the latter, instead of storing a copy (approx. 100 B - 1 kB) of the last transmitted message, should a retransmission
 * 		be warranted the last transition is simply undone and then redone. This is accomplished by using the
 * 		associated functions do_ and undo, respectively.
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

#include <string.h>
#include <stdlib.h>
#include "ipsec_malloc.h"
#include "common_ike.h"
#include "machine.h"
#include "payload.h"
#include "ike.h"
#include "list.h"
#include "sys/ctimer.h"
#include "uip.h"
#include "string.h"

/**
  * IKEv2's behaviour is implemented as a mealy machine. These are its states:
  *
  *
  * Cost of using memory pointers (16 bit pointers):
  *   4 B * session_count   # References for current and past state (RAM)
  *   4 B * state_count     # With the assumption that each state references two other states, on average (ROM)
  *
  * Cost of using enums (8 bit enums, 16 bit pointers):
  *   4 B * session_count   # State id and state 
  *   2 B * state_count     # With the assumption that each state references two other states, on average
  */

#define SET_RETRANSTIMER(session) \
  ctimer_set(&session->retrans_timer, IKE_STATEM_TIMEOUT, &ike_statem_timeout_handler, (void *) session);
#define STOP_RETRANSTIMER(session) ctimer_stop(&(session)->retrans_timer)

#define SA_INDEX(arg) arg - 1


// Initialize the session table
LIST(sessions);

// Network stuff
static const uint8_t *udp_buf = &uip_buf[UIP_LLH_LEN + UIP_IPUDPH_LEN];
uint8_t *msg_buf;
static struct uip_udp_conn *my_conn;
const uip_ip6addr_t *my_ip_addr = &((struct uip_ip_hdr *) &uip_buf[UIP_LLH_LEN])->destipaddr;
const uip_ip6addr_t *peer_ip_addr = &((struct uip_ip_hdr *) &uip_buf[UIP_LLH_LEN])->srcipaddr;

extern uint16_t uip_slen;

// State machine declaration
// IKE_STATEM_DECLARE_STATEFN(name, type)
// ike_statem_statefn_ret_t ike_statem_##name##_##type##(ike_statem_session_t *session)

// Function declarations for providing hints to code in the upper parts of this file
void ike_statem_send(ike_statem_session_t *session, uint16_t len);
void ike_statem_timeout_handler(void *session);


/**
  * To be called in order to enter a _state_ (not execute a transition!)
  */
void ike_statem_enterstate(ike_statem_session_t *session)
{                                        	
  /* Stop retransmission timer (if any has been set) */
  PRINTF(IPSEC_IKE "Session %p is entering state %p\n", (session), (session)->next_state_fn);
	STOP_RETRANSTIMER((session));                               

	/* Were we waiting for a reply? If so, then our last message must have gone through. Increase our message ID. */
	if (session->transition_fn != NULL) {
		IKE_STATEM_INCRMYMSGID(session);                          
		session->transition_fn = NULL;
	}
	                                                            
  state_return_t rtvl = (*(session)->next_state_fn)(session); 
  if (rtvl != STATE_SUCCESS) {                                
    /*                                                        
    if (rtvl != STATE_ERR_NO_NOTIFY) {                        
      transition_return_t len = ike_statem_send_single_notify(session, (rtvl); 
      session->transition_fn = &ike_statem_trans_authreq;                      
      ike_statem_run_transition(ike_statem_session_t *session, 0)              
    }                                                                          
    */                                                                         
    PRINTF(IPSEC_IKE "Removing IKE session %p due to termination in state %p\n", session, (session)->next_state_fn);
    ike_statem_remove_session(session);
  }                                    
  else                                 
    IKE_STATEM_INCRPEERMSGID(session); 
	return;
}


/**
  * Executes a state transition, moving from one state to another and sends a
  * an IKE message in the process. The session as referred to by the variable session is removed (and therefore deallocated)
  * upon transition failure.
  *
  * \param session The session concerned
  * \param retransmit If set to non-zero, the retransmission timer for the transition will be activated. 0 otherwise.
  *
  * \return the value returned by the transition
  */
transition_return_t ike_statem_run_transition(ike_statem_session_t *session, uint8_t retransmit)
{
  PRINTF(IPSEC_IKE "Entering transition fn %p of IKE session %p\n", session->transition_fn, session);  \

  transition_return_t len = (*(session)->transition_fn)(session);

  if (len == TRANSITION_FAILURE) {
    PRINTF(IPSEC_IKE_ERROR "An error occurred while in transition\n");
    ike_statem_remove_session(session);
    return len;
  }

  /* send udp pkt here */
  PRINTF(IPSEC_IKE "Sending data of length %u\n", len);
  /* MEMPRINTF("SENDING", msg_buf, len); */
  ike_statem_send(session, len);
  if (retransmit)
    SET_RETRANSTIMER(session);
  return len;
}



/**
  * Next free value for IKE SPI allocation. To be incremented upon creation of a new IKE SA.
  */
//uint16_t next_my_spi;

// Initialize the state machine
void ike_statem_init()
{
  list_init(sessions);
  srand(clock_time());
  //next_my_spi = rand16() & ~IKE_STATEM_MYSPI_I_MASK;
  
  // Set up the UDP port for incoming traffic
  printf("ike_statem_init: calling udp_new\n");
  my_conn = udp_new(NULL, UIP_HTONS(0), NULL);
  udp_bind(my_conn, UIP_HTONS(IKE_UDP_PORT)); // This will set lport to IKE_UDP_PORT

  my_conn->rport = 0;
  uip_create_unspecified(&my_conn->ripaddr);

  msg_buf = uip_udp_buffer_dataptr(); //(uint8_t *) udp_buf;       

  PRINTF(IPSEC_IKE "State machine initialized. Listening on UDP port %d.\n", uip_ntohs(my_conn->lport));  
}

ike_statem_session_t *ike_statem_session_init()
{
	PRINTF(IPSEC_IKE "Allocating memory for IKE session struct\n");
  ike_statem_session_t *session = ipsec_malloc(sizeof(ike_statem_session_t));

	if (session == NULL) {
		PRINTF(IPSEC_IKE_ERROR "Could not initiate IKE session\n");
		return NULL;
	}
		
  PRINTF(IPSEC_IKE "Initiating IKE session %p\n", session);
  list_push(sessions, session);

  // Set the SPIs.
  session->peer_spi_high = 0U;
  session->peer_spi_low = 0U;
  IKE_STATEM_MYSPI_SET_NEXT(session->initiator_and_my_spi);

  session->my_msg_id = session->peer_msg_id = 0;

	PRINTF(IPSEC_IKE "Allocating memory for IKE session ephemeral info struct\n");
  // malloc() will do as this memory will soon be freed and thus won't clog up the heap for long.
  session->ephemeral_info = ipsec_malloc(sizeof(ike_statem_ephemeral_info_t));

	if (session->ephemeral_info == NULL) {
		PRINTF(IPSEC_IKE_ERROR "Could not allocate memory for ephemeral data structures\n");
		return NULL;
	}
	
  // This random seed will be used for generating our nonce
  session->ephemeral_info->my_nonce_seed = rand16();
   
  /**
    * Generate the private key
    *
    * We're not interested in reusing the DH exponentials across sessions ("2.12.  Reuse of Diffie-Hellman Exponentials")
    * as the author finds the cost of storing them in memory exceeding the cost of the computation.
    */
  PRINTF(IPSEC_IKE "Generating private ECC key\n");
  ecc_gen_private_key(session->ephemeral_info->my_prv_key);

  return session;
}


/**
  * Sets up a new session to handle an incoming request
  */
void ike_statem_setup_responder_session()
{
  ike_statem_session_t *session = ike_statem_session_init();

	if (session == NULL)
		return;

  // We're the responder
  IKE_STATEM_MYSPI_SET_R(session->initiator_and_my_spi);

  memcpy(&session->peer, peer_ip_addr, sizeof(uip_ip6addr_t));

  // Transition to state initrespwait
  session->next_state_fn = &ike_statem_state_parse_initreq;
  session->my_msg_id = 0;
  session->peer_msg_id = 0;

  ike_statem_enterstate(session);
}


/**
  * Initializes an new IKE session with the purpose of creating an SA in response to triggering_pkt_addr
  * and commanding_entry
  */
void ike_statem_setup_initiator_session(ipsec_addr_t *triggering_pkt_addr, spd_entry_t *commanding_entry)
{
  ike_statem_session_t *session = ike_statem_session_init();

  if (session == NULL)
		return;

  // Populate the session entry
  memcpy(&session->peer, triggering_pkt_addr->peer_addr, sizeof(uip_ip6addr_t));
  
  // We're the initiator
  IKE_STATEM_MYSPI_SET_I(session->initiator_and_my_spi);
  
  // Transition to state initrespwait
  session->transition_fn = &ike_statem_trans_initreq;
  session->next_state_fn = &ike_statem_state_initrespwait;
  
  // Populate the ephemeral information with connection setup information  
  memcpy(&session->peer, triggering_pkt_addr->peer_addr, sizeof(uip_ip6addr_t));

  session->ephemeral_info->spd_entry = commanding_entry;
  session->my_msg_id = 0;
  session->peer_msg_id = 0;

  IKE_STATEM_TRANSITION(session);
}

void ike_statem_remove_session(ike_statem_session_t *session)
{
  STOP_RETRANSTIMER(session);   // It might be active, producing accidential transmissions
  list_remove(sessions, session);
}


/**
  * Clean an IKE session when the SA has been established
  */
void ike_statem_clean_session(ike_statem_session_t *session)
{
	PRINTF(IPSEC_IKE "Freeing IKE session's emphemeral information\n");
  ipsec_free(session->ephemeral_info);
}


/**
  * Timeout handler for state transitions (i.e. UDP messages that go unanswered)
  */
void ike_statem_timeout_handler(void *session)  // Void argument since we're called by ctimer
{
  PRINTF(IPSEC_IKE "Timeout for session %p. Reissuing last transition.\n", session);
  ike_statem_run_transition((ike_statem_session_t *) session, 1);
}


/**
  * Traverses the list sessions, starting at head, returning the address of the first
  * entry with matching IPv6 address.
  *
  * \parameter addr Sought IPv6 address
  */
ike_statem_session_t *ike_statem_get_session_by_addr(uip_ip6addr_t *addr)
{
  ike_statem_session_t *session;
  
  for (session = list_head(sessions);
      session != NULL;
      session = list_item_next(session)) {
    uint8_t i;
    for(i = 0; i < sizeof(uip_ip6addr_t); ++i) {
      if(memcmp((const void *) &session->peer, (const void *) addr, sizeof(uip_ip6addr_t)) == 0)
        return session;
    }
  }

  return NULL;
}

/**
  * Get a session by the initiator's SPI
  */
/*
ike_statem_session_t *ike_statem_find_session(uint32_t initiator_spi) {
  ike_statem_session_t *session;
  for (session = list_head(sessions); 
        session != NULL && session->initiator_spi != initiator_spi; 
        session = list_item_next(session))
    ;
  return session;
}
*/



/**
  * Handler for incoming UDP traffic. Matches the data with the correct session (state machine)
  * using the IKE header.
  */
void ike_statem_incoming_data_handler()//uint32_t *start, uint16_t len)
{
  // Get the IKEv2 header
  ike_payload_ike_hdr_t *ike_hdr = (ike_payload_ike_hdr_t *) udp_buf;
  
  /**
    * The message that we've received is sent with the purpose of establishing
    * a new session or request something in relation to an existing one.
    *
    * We only regard the lower 32 bits of the IKE SPIs because I think it'll be enough to
    * distinguish them
    */  
  if (ike_hdr->sa_responder_spi_low == 0 && IKE_PAYLOADFIELD_IKEHDR_FLAGS_INITIATOR & ike_hdr->flags) {
    // The purpose of this request is to setup a new IKE session.

    PRINTF(IPSEC_IKE "Handling incoming request for a new IKE session\n");
    ike_statem_setup_responder_session();
    return;
  }
  
  // So, the request is concerns an existing session. Find the session struct by matching the SPIs.
  uint32_t my_spi = 0;
  if (IKE_PAYLOADFIELD_IKEHDR_FLAGS_INITIATOR & ike_hdr->flags) {
    // The other party is the original initiator
    my_spi = uip_ntohl(ike_hdr->sa_responder_spi_low);
  }
  else {
    // The other party is the responder
    my_spi = uip_ntohl(ike_hdr->sa_initiator_spi_low);
  }

  PRINTF(IPSEC_IKE "Handling incoming request concerning local IKE SPI %u\n", my_spi);

  ike_statem_session_t *session = NULL;
  for (session = list_head(sessions); 
        session != NULL && !IKE_STATEM_MYSPI_GET_MYSPI(session) == my_spi; 
        session = list_item_next(session))
    PRINTF("SPI in list: %u\n", IKE_STATEM_MYSPI_GET_MYSPI(session));

  if (session != NULL) {
    // We've found the session struct of the session that the message concerns
      
    // Assert that the message ID is correct
    if (ike_hdr->flags & IKE_PAYLOADFIELD_IKEHDR_FLAGS_RESPONDER) {
      // It's response to something we sent. Does it have the right message ID?
      if (uip_ntohl(ike_hdr->message_id) != session->my_msg_id) {
        PRINTF(IPSEC_IKE_ERROR "Response message ID is out of order. Dropping it. (expected %u)\n", session->my_msg_id);
        return;
      }
    }
    else {  
      // It's a request
      if (uip_ntohl(ike_hdr->message_id) != session->peer_msg_id) {
        PRINTF(IPSEC_IKE_ERROR "Request message ID is out of order. Dropping it. (expected %u)\n", session->peer_msg_id);
        return;
      }
    }
    
    ike_statem_enterstate(session);
  }
  else {
    PRINTF(IPSEC_IKE_ERROR "We didn't find the session.\n");
    /**
      * Don't send any notification.
      * We're not sending any Notification regarding this dropped message. 
      * See section 1.5 "Informational Messages outside of an IKE SA" for more information.
      */
  }
}

/**
  * Send an UDP packet with the data currently stored in udp_buf (length derived from len)
  * to IP address session->peer
  */
void ike_statem_send(ike_statem_session_t *session, uint16_t len)
{
  uip_udp_buffer_set_datalen(len);
	
	#if IPSEC_TIME_STATS
  uint32_t cpu = energest_type_time(ENERGEST_TYPE_CPU);
  uint32_t transmit = energest_type_time(ENERGEST_TYPE_TRANSMIT);
	#endif

 	uip_udp_buffer_sendto(my_conn, &session->peer, uip_htons(IKE_UDP_PORT));

	#if IPSEC_TIME_STATS
  cpu = energest_type_time(ENERGEST_TYPE_CPU) - cpu;
  transmit = energest_type_time(ENERGEST_TYPE_TRANSMIT) - transmit;

	uint32_t arch_second = RTIMER_ARCH_SECOND;
	printf(IPSEC_IKE "Transmission time: CPU time %u, TRANSMIT time: %u, arch second(?) %u\n", cpu, transmit, arch_second);
	#endif
}

/** @} */