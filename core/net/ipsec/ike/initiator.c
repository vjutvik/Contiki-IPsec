/**
 * \addtogroup ipsec
 * @{
 */

/**
 * \file
 * 		State functions for the machine that initiates IKEv2 sessions
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

#include "sad.h"
#include "common_ike.h"
#include "auth.h"
#include "spd_conf.h"
#include "ecc/ecc.h"
#include "ecc/ecdh.h"

transition_return_t ike_statem_trans_authreq(ike_statem_session_t *session);
state_return_t ike_statem_state_authrespwait(ike_statem_session_t *session);


// Transmit the IKE_SA_INIT message: HDR, SAi1, KEi, Ni
// If cookie_payload in ephemeral_info is non-NULL the first payload in the message will be a COOKIE Notification.
transition_return_t ike_statem_trans_initreq(ike_statem_session_t *session)
{
  payload_arg_t payload_arg = {
    .start = msg_buf,
    .session = session
  };
  
  ike_payload_ike_hdr_t *ike_hdr = (ike_payload_ike_hdr_t *) payload_arg.start;
  SET_IKE_HDR_AS_INITIATOR(&payload_arg, IKE_PAYLOADFIELD_IKEHDR_EXCHTYPE_SA_INIT, IKE_PAYLOADFIELD_IKEHDR_FLAGS_REQUEST);

  return ike_statem_send_sa_init_msg(session, &payload_arg, ike_hdr, (spd_proposal_tuple_t *) CURRENT_IKE_PROPOSAL);
}


/**
  * 
  * INITRESPWAIT --- (AUTHREQ) ---> AUTHRESPWAIT
  *              --- (INITREQ) ---> AUTHRESPWAIT
  */
uint8_t ike_statem_state_initrespwait(ike_statem_session_t *session)
{
  // If everything went well, we should see something like
  // <--  HDR, SAr1, KEr, Nr, [CERTREQ]

  // Otherwise we expect a reply like 
  // COOKIE or INVALID_KE_PAYLOAD  
  
  ike_payload_ike_hdr_t *ike_hdr = (ike_payload_ike_hdr_t *) msg_buf;

  // Store the peer's SPI (in network byte order)
  session->peer_spi_high = ike_hdr->sa_responder_spi_high;
  session->peer_spi_low = ike_hdr->sa_responder_spi_low;
  
  //
  if (ike_statem_parse_sa_init_msg(session, ike_hdr, session->ephemeral_info->ike_proposal_reply) == 0)
    return 0;

  // Jump
  // Transition to state autrespwait
  session->transition_fn = &ike_statem_trans_authreq;
  session->next_state_fn = &ike_statem_state_authrespwait;

  IKE_STATEM_TRANSITION(session);
    
  return 1;

  // This ends the INIT exchange. Borth parties have now negotiated the IKE SA's parameters and created a common DH secret.
  // We will now proceed with the AUTH exchange.
}


// Transmit the IKE_AUTH message:
//    HDR, SK {IDi, [CERT,] [CERTREQ,]
//      [IDr,] AUTH, SAi2, TSi, TSr}
uint16_t ike_statem_trans_authreq(ike_statem_session_t *session) {
  payload_arg_t payload_arg = {
    .start = msg_buf,
    .session = session
  };
  
  // Write the IKE header
  SET_IKE_HDR_AS_INITIATOR(&payload_arg, IKE_PAYLOADFIELD_IKEHDR_EXCHTYPE_IKE_AUTH, IKE_PAYLOADFIELD_IKEHDR_FLAGS_REQUEST);

  return ike_statem_send_auth_msg(session, &payload_arg, session->ephemeral_info->my_child_spi, session->ephemeral_info->spd_entry->offer, &session->ephemeral_info->spd_entry->selector);
}


/**
  * AUTH response wait state
  */
state_return_t ike_statem_state_authrespwait(ike_statem_session_t *session)
{
  // If everything went well, we should see something like
  // <--  HDR, SK {IDr, [CERT,] AUTH, SAr2, TSi, TSr}
  if (ike_statem_parse_auth_msg(session) == STATE_SUCCESS) {
    
    // Remove stuff that we don't need
    ike_statem_clean_session(session);
  
    // Transition to state autrespwait
    session->transition_fn = NULL;
    session->next_state_fn = &ike_statem_state_established_handler;

    return STATE_SUCCESS;
  }

  return STATE_FAILURE;
}


/** @} */
