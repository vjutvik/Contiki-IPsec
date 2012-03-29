#include "sa.h"

typedef struct {
  sa_integ_transform_type_t type;
  uint8_t *data;         // The start of the data
  uint16_t datalen;      // the length of the data
  uint8_t *keymat;       // The start of the KEYMAT
  uint8_t *out;         // Where the output will be written. IPSEC_ICVLEN bytes will be written.
} integ_data_t;

void integ(integ_data_t *data); 
