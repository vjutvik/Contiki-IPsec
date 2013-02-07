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

/**
  * IKEv2 ID 
  */
extern const uint8_t ike_auth_sharedsecret[32];
extern const uint8_t ike_id[16];

extern void auth_psk(uint8_t transform, prf_data_t *auth_data);


/**
  * Authentication methods used in the IKE AUTH payload
  */
typedef enum {
     IKE_AUTH_METHOD_RSA_SIG = 1,
    /*
        Computed as specified in Section 2.15 using an RSA private key
        with RSASSA-PKCS1-v1_5 signature scheme specified in [PKCS1]
        (implementers should note that IKEv1 used a different method for
        RSA signatures).  To promote interoperability, implementations
        that support this type SHOULD support signatures that use SHA-1
        as the hash function and SHOULD use SHA-1 as the default hash
        function when generating signatures.  Implementations can use the
        certificates received from a given peer as a hint for selecting a
        mutually understood hash function for the AUTH payload signature.
        Note, however, that the hash algorithm used in the AUTH payload
        signature doesn't have to be the same as any hash algorithm(s)
        used in the certificate(s).
      */
      
     IKE_AUTH_SHARED_KEY_MIC,
      /*
        Shared Key Message Integrity Code
        Computed as specified in Section 2.15 using the shared key
        associated with the identity in the ID payload and the negotiated
        PRF.
       */
       
     IKE_AUTH_DSS_SIG
      /*
        Computed as specified in Section 2.15 using a DSS private key
        (see [DSS]) over a SHA-1 hash.
      */
} ike_auth_type_t;

/** @} */
