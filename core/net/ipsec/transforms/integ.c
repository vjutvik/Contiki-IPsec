#include "integ.h"
#include "ipsec.h"

extern void aes_xcbc(integ_data_t *data);
extern void hmac_sha1(integ_data_t *data); 

void integ(integ_data_t *data)
{
  data->keylen = SA_INTEG_KEYMATLEN_BY_TYPE(data->type);
  switch(data->type) {
    //case SA_INTEG_HMAC_SHA1_96:         // MUST         MUST          IMPLEMENTED
    //hmac_sha1(data);
    break;
  
    case SA_INTEG_AES_XCBC_MAC_96:          // SHOULD+      SHOULD+       IMPLEMENTED
    aes_xcbc(data);
    break;
    
    default:
    PRINTF(IPSEC "Error: Integrity transform not supported\n");
    //SA_INTEG_HMAC_MD5_95 = 1,          // MAY          MAY           NOT IMPLEMENTED
  }
}

