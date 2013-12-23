/**
 * \addtogroup ipsec
 * @{
 */

/**
 * \file
 * 		State functions for the machine that responds to IKEv2 connections
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

#include "common_ike.h"
#include "spd_conf.h"
#include "ecc/ecc.h"
#include "ecc/ecdh.h"

state_return_t ike_statem_state_parse_initreq(ike_statem_session_t *session)
{
  // We expect to receive something like
  // HDR, SAi1, KEi, Ni  -->

  PRINTF(IPSEC_IKE "ike_statem_state_respond_start: Entering\n");
  
  ike_payload_ike_hdr_t *ike_hdr = (ike_payload_ike_hdr_t *) msg_buf;

  // Store the peer's SPI (in network byte order)
  session->peer_spi_high = ike_hdr->sa_initiator_spi_high;
  session->peer_spi_low = ike_hdr->sa_initiator_spi_low;
  
  if (ike_statem_parse_sa_init_msg(session, ike_hdr, session->ephemeral_info->ike_proposal_reply) == 0)
    return STATE_FAILURE;
  
  session->transition_fn = &ike_statem_trans_initresp; 
  session->next_state_fn = &ike_statem_state_parse_authreq;

  IKE_STATEM_TRANSITION(session);
    
  return STATE_SUCCESS;
}


transition_return_t ike_statem_trans_initresp(ike_statem_session_t *session)
{
  payload_arg_t payload_arg = {
    .start = msg_buf,
    .session = session
  };
  
  ike_payload_ike_hdr_t *ike_hdr = (ike_payload_ike_hdr_t *) payload_arg.start;
  SET_IKE_HDR_AS_RESPONDER(&payload_arg, IKE_PAYLOADFIELD_IKEHDR_EXCHTYPE_SA_INIT, IKE_PAYLOADFIELD_IKEHDR_FLAGS_RESPONSE);
    
  return ike_statem_send_sa_init_msg(session, &payload_arg, ike_hdr, session->ephemeral_info->ike_proposal_reply);
}


state_return_t ike_statem_state_parse_authreq(ike_statem_session_t *session)
{
  if (ike_statem_parse_auth_msg(session) == STATE_SUCCESS) { 
    session->transition_fn = &ike_statem_trans_authresp;
    session->next_state_fn = &ike_statem_state_established_handler;
    
    IKE_STATEM_TRANSITION_NO_TIMEOUT(session);    // We're about to send a new message
    //IKE_STATEM_INCRPEERMSGID(session);  // Since we've recognized the peer's message
    
    // FIX: We need to cleanup here, but how do we handle retransmissions of the above transition?
    // This is an unsolved problem as of now, but it can be fixed by allowing the session struct to
		// remain for some time and only remove it when we are certain that the peer has finished.
		// Remove stuff that we don't need    
		ike_statem_clean_session(session);	// Ignoring problem described above as for now
    
    return STATE_SUCCESS;
  }
  else
    return STATE_FAILURE;
}

transition_return_t ike_statem_trans_authresp(ike_statem_session_t *session)
{
  payload_arg_t payload_arg = {
    .start = msg_buf,
    .session = session
  };
  
  // Write the IKE header
  SET_IKE_HDR_AS_RESPONDER(&payload_arg, IKE_PAYLOADFIELD_IKEHDR_EXCHTYPE_IKE_AUTH, IKE_PAYLOADFIELD_IKEHDR_FLAGS_RESPONSE);
  
  return ike_statem_send_auth_msg(session, &payload_arg, session->ephemeral_info->my_child_spi, session->ephemeral_info->child_proposal_reply, &session->ephemeral_info->my_ts_offer_addr_set);
}

/** @} */
