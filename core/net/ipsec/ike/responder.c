#include "common_ike.h"
#include "spd_conf.h"
#include "ecc/ecc.h"
#include "ecc/ecdh.h"

uint8_t ike_statem_state_parse_initreq(ike_statem_session_t *session)
{
  // We expect to receive something like
  // HDR, SAi1, KEi, Ni  -->

  PRINTF(IPSEC_IKE "ike_statem_state_respond_start: Entering\n");
  
  ike_payload_ike_hdr_t *ike_hdr = (ike_payload_ike_hdr_t *) msg_buf;

  // Store the peer's SPI (in network byte order)
  session->peer_spi_high = ike_hdr->sa_responder_spi_high;
  session->peer_spi_low = ike_hdr->sa_responder_spi_low;
  
  if (ike_statem_parse_sa_init_msg(session, ike_hdr, session->ephemeral_info->proposal_reply) == 0)
    return 0;
  
  session->transition_fn = NULL; //&ike_statem_trans_authreq;
  session->next_state_fn = NULL;//&ike_statem_state_authrespwait;

  //session->transition_arg = &session_trigger;

  IKE_STATEM_INCRMYMSGID(session);
  IKE_STATEM_TRANSITION(session);
    
  return 1;
}