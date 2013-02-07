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


#include "encr.h"
#include "prf.h"
#include "aes-moo.h"

extern void aes_ctr(encr_data_t *encr_data);

/**
  * Pads the end of an ESP or SK payload with the monotonically increasing byte pattern
  * 1, 2, 3, 4... as described in RFC 4303 p. 15. The pad length field will be populated accordingly,
  * and, if non-zero, the ip_next_hdr field will be written.
  *
  * data.encr_datalen and data.tail will be updated accordingly.
  */
static void espsk_pad(encr_data_t *data, uint8_t blocklen)
{
  //PRINTF("Pad: adjusting encr_datalen %u B (+ 1 + ip_next_hdr) to %u B boundary\n", data->encr_datalen, blocklen);
  //PRINTF("data->encr_data %4x\n", data->encr_data);
  uint8_t *tail = data->encr_data + data->encr_datalen;
  //PRINTF("tail at %4x\n", tail);

  uint8_t hdrlen = 1 + (data->ip_next_hdr > 0);
  uint8_t pad = blocklen - (data->encr_datalen + hdrlen) % 4;
  
  // Write the 1, 2, 3... pattern
  uint8_t n;
  for (n = 0; n <= pad; ++n)
    tail[n] = n + 1;
  
  tail += pad + hdrlen;
  data->encr_datalen += pad + hdrlen;
  data->padlen = pad;
  //PRINTF("tail at %4x\n", tail);
  if (data->ip_next_hdr) {
    // negative indices... undefined behaviour across compilers, but this works in mspgcc
    tail[-1] = *data->ip_next_hdr;
    tail[-2] = pad;
  }
  else
    tail[-1] = pad;
  //printf("Pad: Encr_datalen %u\n", data->encr_datalen);
}

/**
  * Reads the trailing headers and adjust data.encr_datalen, data.tail and data.ip_next_hdr
  */
static void espsk_unpad(encr_data_t *data)
{
  if (data->ip_next_hdr) {
    // Next header comes last
    data->ip_next_hdr = data->encr_data + data->encr_datalen - 1;
    data->padlen = *(data->encr_data + data->encr_datalen - 2);
  }
  else {
    // No next header
    data->padlen = *(data->encr_data + data->encr_datalen - 1);
  }
  //printf("Pad: ip_next_hdr %hu padlen %hu\n", *(data->ip_next_hdr), data->padlen);
  
  // According to the RFC of ESP we SHOULD check that the padding pattern is correct (p. 15),
  // (presumably to assert correct cryptographic handling) but I don't see that we can afford it.
  // The pattern is specific to each transform, requiring something more than just a plain for-loop.
}

/**
  * The Encryption payload of IKEv2 (abbreviated SK) is closely modelled upon the ESP header of IPsec. This is true in
  * regard to transforms as well as the wire format. The unpack (used in conjunction with incoming traffic) and the
  * pack (for outgoing) functions in this file can handle both formats.
  *
  * The functions accepts an argument of type *encr_data_t. Please see espsk.h for an explanation of
  * the significance of this struct's members.
  *
  */

/**
  * Takes the data at data->data + block-size and encrypts it in situ, adding padding at the end.
  * This is what the memory will look like after the function has returned:
  *
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ~                    Encrypted IKE Payloads                     ~
    +               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |               |             Padding (0-255 octets)            |
    +-+-+-+-+-+-+-+-+                               +-+-+-+-+-+-+-+-+
    |                                               |  Pad Length   |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  *
  * \return The number of bytes encrypted (the length of the fields Encrypted IKE Payloads (including the IV), Padding and Pad Length).
  */
void espsk_pack(encr_data_t *data)
{  
  switch(data->type) {
    case SA_ENCR_AES_CBC:
    // Confidentiality only

    espsk_pad(data, 16);  // CBC has a block size of 16 bytes
    random_ike(data->encr_data, 16, 0); // CBC prefers a random IV FIX: Assert that MR doesn't write the IV

    // Calculate the number of blocks to encrypt.
    // (data->datalen / 16) - 1 (for the IV whose length is part of datalen) + 1 (one extra block since integer division rounds downwards)
    // This will also allow space for the one byte padding field.
    uint16_t blocks = data->encr_datalen >> 4;
    uint16_t total_bytes = blocks << 4;

    // Write padding information to the last byte of the last block
    data->encr_data[total_bytes - 1] = total_bytes - data->encr_datalen - 1;
    
    // The AES decryption assumes a key length of 16 bytes (128 bit)
    CRYPTO_AES.init(data->keymat);
   
    // Iterate over the 128 bit blocks
    uint16_t n;
    for (n = 1; n < blocks; ++n)
      CRYPTO_AES.encrypt(&data->encr_data[n << 4]);
      
    /*
    // AES encryption using MIRACLE start
    aes a;
    espsk_pad(data, 16);  // CBC has a block size of 16 bytes
    random_ike(data->encr_data, 16, NULL); // CBC prefers a random IV FIX: Assert that MR doesn't write the IV
    aes_init(&a, MR_CBC, data->keymatlen, data->keymat, data->encr_data); // We ignore the exit status

    // Calculate the number of blocks to encrypt.
    // (data->datalen / 16) - 1 (for the IV whose length is part of datalen) + 1 (one extra block since integer division rounds downwards)
    // This will also allow space for the one byte padding field.
    uint16_t blocks = data->datalen >> 4;  // This shift operation (unfortunately) shares information with SA_ENCR_CURRENT_IVLEN(session)
    uint16_t total_bytes = blocks << 4;

    // FIX: Padding needs to be taken care of. What facilities are there in MR for this?
    
    // Write padding information to the last byte of the last block
    data->data[total_bytes - 1] = total_bytes - data->datalen - 1;
    
    // Iterate over the 128 bit blocks
    for (uint16_t n = 1; n < blocks; ++n)
      aes_encrypt(&a, data->data[n << 4]);
      
    aes_end(&a);
    // AES encryption using MIRACLE ends
    */
    break;

    case SA_ENCR_AES_CTR:         // SHOULD
    // Confidentiality only

    // Pad the data for 32 bit-word alignment, add trailing headers and adjust encr_datalen accordingly
    espsk_pad(data, 4);
    *((uint32_t *) data->encr_data) = data->ops; // AES CTR's IV must be unique, but not necessarily random.

    // Encrypt everything from encr_data continuing for encr_datalen bytes
    aes_ctr(data);
    break;
    
    case SA_ENCR_NULL:
    espsk_pad(data, 4);
    break;
    
    default:
    PRINTF(IPSEC "Error: Unknown encryption type\n");
    /*  
    SA_ENCR_RESERVED = 0,
    SA_ENCR_3DES = 3,             // MUST-
    SA_ENCR_NULL = 11,            // MAY
    SA_ENCR_UNASSIGNED = 255
    */
  }
}


/**
  * Decrypts the data in an SK payload in situ. data.start should point to the IV payload. data.datalen should be the length
  * of the the IV field, the encrypted IKE payload, the padding and the pad length field.
  *
  BEFORE:
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ~                    Encrypted IKE Payloads                     ~
    +               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |               |             Padding (0-255 octets)            |
    +-+-+-+-+-+-+-+-+                               +-+-+-+-+-+-+-+-+
    |                                               |  Pad Length   |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

  AFTER:
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ~                    Decrypted IKE Payloads                     ~
    +               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |               |             Padding (0-255 octets)            |
    +-+-+-+-+-+-+-+-+                               +-+-+-+-+-+-+-+-+
    |                                               |  Pad Length   |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  
  *
  */
void espsk_unpack(encr_data_t *data)
{
  switch(data->type) {
    //case SA_ENCR_AES_CBC:         // SHOULD+

    // The AES decryption assumes a key length of 16 bytes (128 bit)
    // DISABLED due to memory constraints
    /*
    CRYPTO_AES.init(data->keymat);
    
    uint8_t num_blocks = data->encr_datalen >> 4;

    // Iterate over the 128 bit blocks
    uint16_t n;
    for (n = 1; n < num_blocks; ++n)
      CRYPTO_AES.encrypt(&data->encr_data[n << 4]);
    */
    // AES decryption ends

    /*
    // AES decryption with MIRACLE
    aes a;
    aes_init(&a, MR_CBC, data->keymatlen, data->keymat, data->data); // We ignore the exit status

    uint8_t num_blocks = data->datalen >> 4; // This shift operation (unfortunately) shares information with SA_ENCR_CURRENT_IVLEN(session)

    // Iterate over the 128 bit blocks
    for (uint16_t n = 1; n < num_blocks; ++n)
      aes_decrypt(&a, data->data[n << 4]);

    aes_end(&a);
    break;
    */
    
    case SA_ENCR_AES_CTR:         // SHOULD
    // Confidentiality only
    aes_ctr(data);
    break;

    case SA_ENCR_NULL:
    break;

    default:
    PRINTF(IPSEC "Error: Unknown encryption type\n");
    /*  
    SA_ENCR_RESERVED = 0,
    SA_ENCR_3DES = 3,             // MUST-
    SA_ENCR_NULL = 11,            // MAY
    SA_ENCR_AES_CTR = 13,         // SHOULD
    SA_ENCR_UNASSIGNED = 255
    */
  }
  espsk_unpad(data);
}

/** @} */

