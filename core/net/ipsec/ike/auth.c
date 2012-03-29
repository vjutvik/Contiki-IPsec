#include "contiki-conf.h"
/**
  * IKEv2 ID data
  */

// The shared key used in the AUTH payload. To be replaced by a proper PAD implementation.
const uint8_t ike_auth_sharedsecret[32] = "aa280649dc17aa821ac305b5eb09d445";
const uint8_t ike_id[13] = "ville@sics.se";