/**
 * \addtogroup ipsec
 * @{
 */

/**
 * \file
 * 		Authentication for IKEv2
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

/** @} */

