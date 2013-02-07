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

#ifndef __MACHINE_H__
#define __MACHINE_H__

#include "contiki-net.h"
#include "payload.h"
#include "spd.h"
#include "common_ipsec.h"
#include "sa.h"
#include "ecc/ecc.h"
#include "ecc/nn.h"
#include "ipsec_random.h"

#define IKE_UDP_PORT 500


/**
  * Protocol-related stuff
  */
#define IKE_STATEM_TIMEOUT 15 * CLOCK_SECOND

/**
  * Global buffers used for communicating information with the state machine
  */
extern uint8_t *msg_buf; // Pointing at the first word of the UDP datagram's data areas
//extern uip_ip6addr_t *uip_addr6_remote; // IPv6 address of remote peer
extern const uip_ip6addr_t *my_ip_addr;

extern uint8_t *global;


/**
  * Code for state related stuff
  *
  * Each state is associated with a state function. The purpose of said function
  * is to decide, and execute, the next state transition upon an event occurring.
  * For facilitating this decision a pointer to the session struct is passed as an argument
  * and buffers containing UDP messages etc are made available to it.
  */
/*
typedef void ike_statem_statefn_ret_t;//uint16_t *ike_statem_statefn_ret_t;
typedef (ike_statem_session_t *) ike_statem_statefn_args_t;
*/
// Macro for declaring a state function
/*
#define IKE_STATEM_DECLARE_STATEFN(name, type) \
  ike_statem_statefn_ret_t ike_statem_##name##_##type##(ike_statem_session_t *session)
*/


#define IKE_STATEM_MYSPI_MAX 32767 // 15 bits. First bit occupied by initiator / responder. 2^15 - 1

// Macros for manipulating 'initiator_and_my_spi'
#ifdef BIGENDIAN
  #define IKE_STATEM_MYSPI_I_MASK 0x8000
#else
  #define IKE_STATEM_MYSPI_I_MASK 0x0080
#endif

// The maximum size of the peer's first message.
// Used for calculating the AUTH hash
#define IKE_STATEM_FIRSTMSG_MAXLEN 500

// The maximum number of tuples that can be returned in a reply from 
#define IKE_REPLY_MAX_PROPOSAL_TUPLES 10

#define IKE_STATEM_MYSPI_GET_MYSPI(session) ((session)->initiator_and_my_spi & ~IKE_STATEM_MYSPI_I_MASK)
#define IKE_STATEM_MYSPI_GET_MYSPI_HIGH(session) 0U
#define IKE_STATEM_MYSPI_GET_MYSPI_LOW(session) (uip_htonl(((uint32_t) IKE_STATEM_MYSPI_GET_MYSPI(session))))
#define IKE_STATEM_MYSPI_GET_I(var) (var & IKE_STATEM_MYSPI_I_MASK)
#define IKE_STATEM_IS_INITIATOR(session) (IKE_STATEM_MYSPI_GET_I(session->initiator_and_my_spi))
#define IKE_STATEM_MYSPI_SET_I(var) (var = var | IKE_STATEM_MYSPI_I_MASK)
#define IKE_STATEM_MYSPI_SET_R(var) (var = var & ~IKE_STATEM_MYSPI_I_MASK)
#define IKE_STATEM_MYSPI_SET_NEXT(var) (var = (var | (rand16() & ~IKE_STATEM_MYSPI_I_MASK))) /* (next_my_spi++ & ~IKE_STATEM_MYSPI_I_MASK)*/  // (Note: This will overflow into the Initiator bit after 2^15 - 1 calls)
#define IKE_STATEM_MYSPI_CLEAR_I(var) (var = var & ~IKE_STATEM_MYSPI_I_MASK)

typedef uint8_t state_return_t;
typedef uint16_t transition_return_t;

#define STATE_FAILURE        0
#define STATE_SUCCESS        1
#define TRANSITION_FAILURE   0


#define IKE_STATEM_INCRMYMSGID(session) ++(session)->my_msg_id;
#define IKE_STATEM_INCRPEERMSGID(session) ++(session)->peer_msg_id;
#define IKE_STATEM_SESSION_ISREADY(session) (ctimer_expired(&session->retrans_timer))

/**
  * Call this macro when you want to execute a state transition 
  * (i.e. send a request / response).
  *
  * Can either be called from a state or from ike_statem_timeout_handler()
  */
#define IKE_STATEM_TRANSITION(session)                                  \
  /* Run transition */       																						\
  ike_statem_run_transition(session, 1)

#define IKE_STATEM_TRANSITION_NO_TIMEOUT(session)                         \
  /* Run transition */         																						\
  ike_statem_run_transition(session, 0)

/**
  * Storage structure for temporary information used during connection setup.
  */
typedef struct {
  // Information about the triggering packet (used for IKE SA initiation)
  spd_entry_t *spd_entry;
  
  // Temporary storage for our TS offer to the peer
  ipsec_addr_set_t my_ts_offer_addr_set;

  uint32_t my_child_spi;
  uint32_t peer_child_spi;

  // Used for generating the AUTH payload. Length MUST equal the key size of the negotiated PRF.
  uint8_t sk_pi[SA_PRF_MAX_PREFERRED_KEYMATLEN];
  uint8_t sk_pr[SA_PRF_MAX_PREFERRED_KEYMATLEN];

  /**
    * Seed for generating our Nonce. This will effectively cause our multibyte nonce to become a
    * function of this value, thus circumventing the RFC's nonce length requirements, making the cryptographic 
    * protection weaker.
    *
    * This must clearly be fixed in the production code of this software. Though I hope that the principle of
    * generating the nonce on the fly is preserved, alleviating the need to storing an additional ~16 bytes in RAM.
    * Instead of using a single seed value we can add semi-static, semi-random, data from the network layer, the radio,
    * the OS etc.
    */
  uint16_t my_nonce_seed;
  uint8_t peernonce[IKE_PAYLOAD_PEERNONCE_LEN];
  uint8_t peernonce_len;

  uint8_t peer_first_msg[IKE_STATEM_FIRSTMSG_MAXLEN];
  uint16_t peer_first_msg_len;
  
  // Internal representation of our reply to a responder's SA offer
  spd_proposal_tuple_t ike_proposal_reply[IKE_REPLY_MAX_PROPOSAL_TUPLES];
  spd_proposal_tuple_t child_proposal_reply[IKE_REPLY_MAX_PROPOSAL_TUPLES];

  // My private asymmetric key store in small endian ContikiECC format
  NN_DIGIT my_prv_key[IKE_DH_SCALAR_BUF_LEN];
} ike_statem_ephemeral_info_t;


/**
  * Session struct
  */
typedef struct ike_statem_session {
  struct ike_statem_session *next;
  
  // The IPv6 of the peer that we're communicating with
  uip_ip6addr_t peer;
  
  /*
   * This 16 bit variable is an amalgam of two pieces of information:
   
   In big endian systems:
                        1           
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |I|  My SPI                     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

  In little endian systems:
                       1           
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |  My SPI       |I|             |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   * The 'I' flag is set if we're the initator of this IKE session. This may
   * change upon IKE SA rekey.
   *
   * The values are set / read by using the macros as defined above.
   *
   * The My SPI -value is also the key of the linked list.
   */
  uint16_t initiator_and_my_spi;
  
  // The peer's IKE SPI. Is not unique as it's decided by the peer.
  // (Can we remove this 8 B lump? We can't initiate requests without it.)
  uint32_t peer_spi_high, peer_spi_low;


  /**
    * Message ID as described in section 2.2.
    * The values are only 8 bits large, much smaller than 32 bits as dictated by the standard.
    * We believe this is a reasonable tradeof as we don't expect much IKEv2 -traffic
    * to any IKE SA. The SA will be closed, or rekeyed (will we implement this?), in the event 
    * of an overflow (in line with the RFC).
    */
  uint8_t my_msg_id, peer_msg_id;

  // Message retransmission timer
  struct ctimer retrans_timer;

  // IKE SA parameters
  // Note for future functionality: We could make the SA and the whole sa_ike_t
  // of variable size (next and length info in the head, cast everything to smallest
  // common denominator)  
  sa_ike_t sa;

  // Temporary scratchpad for use during setup of the IKE SA
  ike_statem_ephemeral_info_t *ephemeral_info;

  /**
    * Address of COOKIE data. Used by ike_statem_trans_initreq(). The default value should be NULL.
    */
  ike_payload_generic_hdr_t *cookie_payload;

  // The edge (transition) to follow
  uint16_t (*transition_fn)(struct ike_statem_session *);
  
  // The above transition will (if all goes well) take us to this state.
  uint8_t (*next_state_fn)(struct ike_statem_session *);

} ike_statem_session_t;


/**
  * Convenience macros for translating the roles of initiator/responder to myself/peer
  */
#define IKE_STATEM_GET_MY_SK_P(session) (IKE_STATEM_IS_INITIATOR(session) ? session->ephemeral_info->sk_pi : session->ephemeral_info->sk_pr)
#define IKE_STATEM_GET_PEER_SK_P(session) (IKE_STATEM_IS_INITIATOR(session) ? session->ephemeral_info->sk_pr : session->ephemeral_info->sk_pi)
#define IKE_STATEM_GET_MY_SK_A(session) (IKE_STATEM_IS_INITIATOR(session) ? session->sa.sk_ai : session->sa.sk_ar)
#define IKE_STATEM_GET_PEER_SK_A(session) (IKE_STATEM_IS_INITIATOR(session) ? session->sa.sk_ai : session->sa.sk_ar) 
#define IKE_STATEM_GET_MY_SK_E(session) (IKE_STATEM_IS_INITIATOR(session) ? session->sa.sk_ei : session->sa.sk_er)
#define IKE_STATEM_GET_PEER_SK_E(session) (IKE_STATEM_IS_INITIATOR(session) ? session->sa.sk_er : session->sa.sk_ei)

/**
  * Common argument for payload writing functions
  */
typedef struct {
  uint8_t *start;                                 // The address at which the paylaod should start
  ike_statem_session_t *session;                  // Session pointer
  uint8_t *prior_next_payload;                    // Pointer that stores the address of the last "next payload" -field, of type ike_payload_type_t
} payload_arg_t;

ike_statem_session_t *ike_statem_get_session_by_addr(uip_ip6addr_t *addr);
void ike_statem_setup_initiator_session(ipsec_addr_t * triggering_pkt_addr, spd_entry_t * commanding_entry);
void ike_statem_remove_session(ike_statem_session_t *session);
extern void ike_statem_clean_session(ike_statem_session_t *session);
extern void ike_statem_send(ike_statem_session_t *session, uint16_t len);


void ike_statem_init();
void ike_statem_incoming_data_handler();

#endif

/** @} */

