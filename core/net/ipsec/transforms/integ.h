#include "sa.h"

/**
  * prf_data_t is used as the argument struct for integrity calculations.
  *
  * data        is the start of the data
  * datalen     is the length of the data
  * keymat      is the start of the key
  * keymatlen   is the length of the key
  * out         is where the output will be written
  * outlen      should not be used
  */

typedef struct {
  sa_integ_transform_type_t type;
  uint8_t *data;         // The start of the data
  uint16_t datalen;      // the length of the data
  uint8_t *keymat;       // The start of the KEYMAT

  // Length of the _key_ in bytes. Doesn't need to be assigned when calling integ().
  // Please note that the key is merely a subset of keymat which may contain more information such as nonce values etc.
  uint8_t keylen;
  
  uint8_t *out;         // Where the output will be written. IPSEC_ICVLEN bytes will be written.
} integ_data_t;

void integ(integ_data_t *data); 

#define INTEG(data_ptr)                                   \
  do {                                                    \
    data_ptr->outlen = SA_INTEG_KEYLEN;                   \
    prf(data_ptr);                                        \
  } while(0)
