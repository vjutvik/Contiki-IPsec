#include "contiki-conf.h"
/**
  * IKEv2 ID data
  */

// The shared key used in the AUTH payload. To be replaced by a proper PAD implementation.
const uint8_t ike_auth_sharedsecret[32] = "aa280649dc17aa821ac305b5eb09d445";

// The length of ike_id _must_ be a multiple of 4 (as implied in "Identification payload" in RFC 5996)
const uint8_t ike_id[16] = "ville@sics.se   ";