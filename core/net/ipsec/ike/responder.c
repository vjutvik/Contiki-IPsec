#include "common_ike.h"
#include "spd_conf.h"
#include "ecc/ecc.h"
#include "ecc/ecdh.h"

uint8_t ike_statem_state_handle_initreq(ike_statem_session_t *session)
{
  // We expect to receive something like
  // HDR, SAi1, KEi, Ni  -->

  PRINTF(IPSEC_IKE "ike_statem_state_respond_start: Stub!\n");
  return 0;
}