#include <stdlib.h>
#include "sad.h"
#include "common_ike.h"
#include "auth.h"
#include "spd_conf.h"
#include "ecc/ecc.h"
#include "ecc/ecdh.h"


uint8_t ike_statem_state_established_handler(ike_statem_session_t *session)
{
  PRINTF(IPSEC_IKE "Ignoring IKE message sent by peer\n");
  return 1;
}




