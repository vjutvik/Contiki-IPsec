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
