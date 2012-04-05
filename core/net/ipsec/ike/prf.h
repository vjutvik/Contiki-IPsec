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

/*
FIX: Remove this I feel confident about the above typedef
typedef struct {
  uint8_t transform;    // Transform type (only SA_PRF_HMAC_SHA1 implemented as of now)
  uint8_t *out;         // Address to which the output will be written
  uint8_t outlen;       // Desired length of the output (in bytes) (individual restricitions applies to each transforms)
  uint8_t *keymat;      // Address of the key (K)
  uint8_t keymatlen;    // Length of the key
  uint8_t *data;        // Address of the data (S)
  uint16_t datalen;     // Length of the data
} prf_data_t;
*/


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


void prf(sa_prf_transform_type_t prf_type, prf_data_t *data);
void prf_plus(prfplus_data_t *data);
void random_ike(uint8_t *out, uint16_t len, uint16_t seed);
void prf_psk(uint8_t transform, prf_data_t *data);

#endif
