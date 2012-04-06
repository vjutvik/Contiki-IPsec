#include "lib/random.h"

#include "string.h"
#include "contiki-conf.h"
#include "prf.h"
#include "machine.h"
#include "hmac-sha1/hmac-sha1.h"

static const uint8_t auth_keypad[] = "Key Pad for IKEv2";

/**
  * Compute the hash as described in RFC 5996, p. 49:
  *
    AUTH = prf( prf(Shared Secret, "Key Pad for IKEv2"),
                   <InitiatorSignedOctets>)
  *
  * \parameter session The session struct
  * \parameter in Pointer to InitiatorSignedOctets
  * \parameter out The address to where the hash will be written.
  */
/*
void ike_auth_presharedkey_hash(ike_statem_session_t *session, uint8_t *in, uint16_t in_len, uint8_t *out)
{
  switch(session->sa.prf) {
    //case SA_PRF_HMAC_MD5:          // MAY-
    case SA_PRF_HMAC_SHA1:         // MUST

    // FIX: Use prf as defined below

    SHA1Context ctx;
    sha1_reset(&ctx);
    sha1_update(&ctx, gir, IKE_DH_GIR_LEN);
    sha1_digest(&ctx, skeyseed);
    
    //case SA_PRF_AES128_CBC:        // SHOULD+
  }
}
*/

/**
  * Calculate our nonce
  */
/**
  * Write a (sort of) random nonce
  */
/*
uint8_t *mynonce(uint8_t *start, ike_statem_ephemeral_info_t *ephemeral_info)
{
  random_init(ephemeral_info->my_nonce_seed);

  uint16_t ptr = (uint16_t *) start;
  uint16_t end = ptr + IKE_PAYLOAD_MYNONCE_2OCTET_LEN  
  for (; ptr < end; ++ptr)
    ptr = rnd16();
  return ptr; 
}
*/

/**
  * Implementation of AUTH = prf( prf(Shared Secret, "Key Pad for IKEv2"), <*SignedOctets>)
  * as seen on p. 49. Used for authentication with pre-shared keys.
  */
void prf_psk(uint8_t transform, prf_data_t *data)
{
  const uint8_t prf_len = SA_PRF_OUTPUT_LEN_BY_ID(transform);
  uint8_t data_out[prf_len];
  
  prf_data_t keypad_arg = {
    .out = data_out,
    .key = data->key,
    .keylen = data->keylen,
    .data = (uint8_t *) auth_keypad,
    .datalen = sizeof(auth_keypad)
  };
  prf(transform, &keypad_arg);
  
  // prf( prf(Shared Secret, "Key Pad for IKEv2"), <InitiatorSignedOctets>)
  data->key = data_out;
  data->keylen = prf_len;
  
  prf(transform, data);
}

/**
  * Get a random string. Any given output will be reproduced for the same seed and len.
  */
void random_ike(uint8_t *out, uint16_t len, uint16_t seed)
{
  if (seed == 0)
    random_init(123);
  else
    random_init(seed);
  
  uint8_t *ptr;
  for (ptr = out; ptr < out + len; ++ptr)
    *ptr = (uint8_t) random_rand();
}

/**
  * PRF as defined in the RFC
  */
void prf(sa_prf_transform_type_t prf_type, prf_data_t *prf_data)
{
  switch (prf_type) {
    case SA_PRF_HMAC_SHA1:         // MUST

    // FIX: This copy paste thing ain't beautiful. 
    // Make prf and hmac_sha1 use the same datastructures in the future.
    /*
    hmac_data_t hmac_data = {
      .out = prf_data->out,
      .outlen = prf_data->outlen,
      .key = prf_data->key,
      .keylen = prf_data->keylen,
      .data = prf_data->data,
      .datalen = prf_data->datalen
    };
    */
    hmac_sha1(prf_data);
    break;
    
    case SA_PRF_AES128_CBC:      // SHOULD+
    PRINTF(IPSEC "Error: Not implemented\n");
    break;
    
    default:
    PRINTF(IPSEC "Error: Unknown PRF request\n");
  }  
}

/**
  * This is an implementation of the PRF+ function as described in section 2.13 (p. 45)
  * 
  * === snip ===
  
  In the following, | indicates concatenation. prf+ is defined as:

  prf+ (K,S) = T1 | T2 | T3 | T4 | ...

  where:
  T1 = prf (K, S | 0x01)
  T2 = prf (K, T1 | S | 0x02)
  T3 = prf (K, T2 | S | 0x03)
  T4 = prf (K, T3 | S | 0x04)
  ...
  
  * === snip ===
  *
  * \param prf_type The type of PRF. Commonly that negotiated for the SA.
  * \param data The argument data structure, as defined in prf.h
  *
  * The sum of the lengths in chunks_len may NOT exceed 255 * 255
  
  typedef struct {
    sa_prf_transform_type_t prf;
    uint8_t * key;          // Pointer to the key
    uint8_t keylen;         // Pointer to the key len
    uint8_t no_chunks;      // The number of chunks (length of chunks and chunks_len)
    uint8_t * data;         // Pointer to the message
    uint16_t datalen;       // Length of the message
    uint8_t **chunks;       // Pointer to an array of pointers, each pointing to an output chunk N.
    uint8_t *chunks_len;    // Pointer to an array of the lengths of chunk N.
  } prf_plus_data_t;
  
  *
  */


void prf_plus(prfplus_data_t *plus_data)
{
  const uint8_t prf_outputlen = sa_prf_output_len[plus_data->prf];
  
  // Loop over chunks_len and find the longest chunk
  uint16_t chunk_maxlen = 0;
  uint16_t i;
  for (i = 0; i < plus_data->no_chunks; ++i) {
    if (plus_data->chunks_len[i] > chunk_maxlen)
      chunk_maxlen = plus_data->chunks_len[i];
  }
  
  // Set up the buffers
  uint16_t outbuf_maxlen = chunk_maxlen + prf_outputlen;
  uint16_t msgbuf_maxlen = prf_outputlen + plus_data->datalen + 1;   // Maximum length of TN + S + 0xNN
  uint8_t outbuf[outbuf_maxlen];   // The buffer for intermediate storage of the output from the PRF. To be copied into the chunks.
  uint8_t msgbuf[msgbuf_maxlen];   // Assembly buffer for the message
  uint8_t lastout[prf_outputlen];

  // Loop over the chunks
  prf_data_t prf_data = {
    .key = plus_data->key,
    .keylen = plus_data->keylen,
    .data = msgbuf
  };
  uint8_t outbuf_len = 0;  
  uint8_t prf_ctr = 1;
  uint8_t curr_chunk;
  for (curr_chunk = 0; curr_chunk < plus_data->no_chunks; ++curr_chunk) {
//    MEMPRINTF("OUTBUF is now", outbuf, prf_outputlen);
    uint8_t curr_chunk_len = plus_data->chunks_len[curr_chunk];
    
    // Now, how much PRF output data do we need for this chunk? Generate more data if we don't have enough .
    if (curr_chunk_len > outbuf_len) {
      // We need more data in the output buffer
//      MEMPRINTF("OUTBUF is now", outbuf, prf_outputlen);
      
      for (; outbuf_len < curr_chunk_len; outbuf_len += prf_outputlen, ++prf_ctr) {
        
        // Compose the message
        uint8_t *ptr = msgbuf;
//        PRINTF("ptr: %p msgbuf: %p\n", ptr, msgbuf);
        if (prf_ctr > 1) {
          // The message is T(N - 1) | S | 0xN where N is ptr_ctr
          memcpy(ptr, lastout, prf_outputlen); // Copy TN (the last PRF output)
          ptr += prf_outputlen;
        }
        // else: The message is S | 0x01
        // MEMPRINTF("OUTBUF is now (bef msg assembly)", outbuf, prf_outputlen);
        // PRINTF("ptr: %p msgbuf: %p\n", ptr, msgbuf);
        memcpy(ptr, plus_data->data, plus_data->datalen);   // Add S
        // PRINTF("plus_data->datalen: %d, sizeof(msgbuf): %d\n", plus_data->datalen, sizeof(msgbuf));
        // MEMPRINTF("OUTBUF is now(1)", outbuf, prf_outputlen);

        ptr += plus_data->datalen;
        *ptr = prf_ctr;                                     // Add 0xN
        ++ptr;
        // MEMPRINTF("OUTBUF is now(bef prf_data def)", outbuf, prf_outputlen);
        
        // Message compiled. Run the PRF operation.
        prf_data.out = &outbuf[outbuf_len];
        prf_data.datalen = ptr - msgbuf;
        // PRINTF("outputting 20 bytes to %p. outbuf[0] at %p\n", prf_data.out, outbuf);
        prf(plus_data->prf, &prf_data);
        // MEMPRINTF("OUTBUF is now (bfe memcpy)", outbuf, prf_outputlen);
        memcpy(lastout, &outbuf[outbuf_len], prf_outputlen); // Take a copy of this output for use as the next TN string
        // MEMPRINTF("OUTBUF is now (after memcpy)", outbuf, prf_outputlen);
      }
    }
  
    // PRINTF("curr_chunk_len: %d\n", curr_chunk_len);
    // MEMPRINTF("PRF+ OUTPUT", outbuf, prf_outputlen);
    
    // We have exited the loop and... given the complexity of the above loop... 
    // ... we can surmise that outbuf contains enough data to fill plus_data->chunks_len[curr_chunk]
    memcpy(plus_data->chunks[curr_chunk], outbuf, curr_chunk_len); // Copy the data to the chunk
    MEMPRINTF("Chunk is", plus_data->chunks[curr_chunk], curr_chunk_len);
    
    // We have probably left some trailing data in the buffer. Move it to the beginning so as to save it for the next chunk.
    outbuf_len = outbuf_len - curr_chunk_len;
    memmove(outbuf, &outbuf[curr_chunk_len], outbuf_len);
    // PRINTF("outbuf_len: %d\n", outbuf_len);
    // MEMPRINTF("OUTBUF is now", outbuf, prf_outputlen);
    // PRINTF("NEXT CHUNK!\n");
    // if (outbuf_len == 4)
    //   PRINTF("#############################\n");
    
  }
}
