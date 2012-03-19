#include "common_ike.h"
#include "spd_conf.h"
#include "ecc/ecc.h"
#include "ecc/ecdh.h"

uint16_t ike_statem_state_respond_start(void)
{
  // We expect to receive something like
  // HDR, SAi1, KEi, Ni  -->

  PRINTF(IPSEC_IKE "ike_statem_state_respond_start: Stub!\n");
  return 0;
}