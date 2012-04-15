#include "prf.h"
#include "contiki-conf.h"
#include "common_ike.h"
/**
  * IKEv2 ID data
  */

// The shared key used in the AUTH payload. To be replaced by a proper PAD implementation.
const uint8_t ike_auth_sharedsecret[32] = "aa280649dc17aa821ac305b5eb09d445";

// The length of ike_id _must_ be a multiple of 4 (as implied in "Identification payload" in RFC 5996)
const uint8_t ike_id[16] = "ville@sics.se   ";

static const uint8_t auth_keypad[17] = { 'K', 'e', 'y', ' ', 'P', 'a', 'd', ' ', 'f', 'o', 'r', ' ', 'I', 'K', 'E', 'v', '2' };


/**
  * Implementation of AUTH = prf( prf(Shared Secret, "Key Pad for IKEv2"), <*SignedOctets>)
  * as seen on p. 49. Used for authentication with pre-shared keys.
  *
  * auth_data should be set up in the following way:
  *   auth_data->out = out;
  *   auth_data->data = signed_octets;
  *   auth_data->datalen = signed_octets_len;  
  */
void auth_psk(uint8_t transform, prf_data_t *auth_data)
{
  const uint8_t prf_out_len = SA_PRF_OUTPUT_LEN_BY_ID(transform);
  uint8_t data_out[prf_out_len];
  
  // Perform the inner PRF operation
  prf_data_t keypad_arg = {
    .out = data_out,
    .key = ike_auth_sharedsecret,
    .keylen = sizeof(ike_auth_sharedsecret),
    .data = (uint8_t *) auth_keypad,
    .datalen = sizeof(auth_keypad)
  };
  prf(transform, &keypad_arg);

  // Perform the outer PRF operation
  auth_data->key = data_out;
  auth_data->keylen = prf_out_len;
  
  prf(transform, auth_data);
}
