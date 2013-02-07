/**
 * \addtogroup ipsec
 * @{
 */

/**
 * \file
 * 		Implementations of pseudorandom functions for IKEv2 as described in RFC 5996 
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

#ifndef __AUTH_H__
#define __AUTH_H__

#include "sa.h"
#include "hmac-sha1/hmac-sha1.h"

/**
  * Datastructure that defines a PRF(K, S) operation. (where K is key and S is message) as
  * defined in RFC 5996 section 2.13.
  *
  * As of now, the only implemented PRF operation is SA_PRF_HMAC_SHA1 (RFC 5996),
  * but the data structer is built to accomodate any PRF.
  */
typedef hmac_data_t prf_data_t;

typedef struct {
  sa_prf_transform_type_t prf;
  uint8_t * key;          // Pointer to the key
  uint8_t keylen;         // Key length
  uint8_t no_chunks;      // The number of chunks (length of chunks and chunks_len)
  uint8_t * data;         // Pointer to the message
  uint16_t datalen;       // Length of the message
  uint8_t **chunks;       // Pointer to an array of pointers, each pointing to an output chunk N.
  uint8_t *chunks_len;    // Pointer to an array of the lengths of chunk N.
} prfplus_data_t;


void prf(sa_prf_transform_type_t prf_type, prf_data_t *data);
void prf_plus(prfplus_data_t *data);
void random_ike(uint8_t *out, uint16_t len, uint16_t seed);

#endif

/** @} */

