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
  
  session->transition_fn = &ike_statem_trans_initresp; //&ike_statem_trans_authreq;
  session->next_state_fn = &ike_statem_state_parse_authreq;//&ike_statem_state_authrespwait;

  //session->transition_arg = &session_trigger;

  //IKE_STATEM_INCRPEERMSGID(session);
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
    // Remove stuff that we don't need
    // ike_statem_clean_session(session);
    
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