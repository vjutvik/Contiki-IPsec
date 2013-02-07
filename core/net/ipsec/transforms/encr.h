/**
 * \addtogroup ipsec
 * @{
 */

/**
 * \file
 * 		Interface that pads, unpads, encrypts and decrypts ESP headers using any given encryption method
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

#ifndef __ENCR_H__
#define __ENCR_H__

#include "sa.h"
#include "ipsec.h"

/**
  * Data struct used in conjunction with encr() and decr() for writing the IKE Encrypted (SK) payload
  * and the ESP header of IPsec.
  *
  * Please note that ip_next_hdr MUST be set to indicate ESP or SK when using encr() _as well as_ decr()
  */
typedef struct {
  // Algorithm
  sa_encr_transform_type_t type;
  uint8_t *keymat; // KEYMAT is the source of the key + other necessary information
  
  // Length of the _key_ in bytes. Always assigned, irrespective of if the transform has static or dynamic key length.
  // Please note that the key is merely a subset of keymat which may contain more information such as nonce values etc.
  uint8_t keylen;
  
  // Integrity
  // integ_datalen will be encr_datalen + (encr_data - integ_data)
  uint8_t *integ_data;       // Beginning of the ESP header (ESP) or the IKEv2 header (SK)
  
  // Confidentiality
  uint8_t *encr_data;        // The beginning of the IV
  uint16_t encr_datalen;     // From the beginning of the IV to the IP next header field (ESP) or the padding field (SK).
  
  // Next Header for ESP. If this pointer is set to NULL the IKE SK format is used, ESP otherwise.
  // Is to be trusted on output.
  uint8_t *ip_next_hdr;
  
  uint32_t ops;          // Number of operations that have been performed utilizing this key. Used for IV in some transforms.
  
  /**
    * Information that is to be filled by the called (callee) function (encr_pad and encr_unpad).
    * The caller can leave the fields as-is upon calling the functions.
    */
  // ICV information to be filled by the callee. Only used in unpacking.
  uint8_t icv[IPSEC_ICVLEN];
  uint8_t padlen;  // Length of padding (number of bytes between end of decrypted data and padding field)
} encr_data_t;


void espsk_unpack(encr_data_t *data);
void espsk_pack(encr_data_t *data);

#endif


/** @} */

