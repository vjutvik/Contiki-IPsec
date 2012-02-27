#ifndef __MESSAGES_H__
#define __MESSAGES_H__

#include "nn.h"

typedef struct {
 unsigned char data[2]; 
} nw_uint16_t;

typedef struct msg_header 
{
  NN_DIGIT r[NUMWORDS];
  NN_DIGIT s[NUMWORDS];
  nw_uint16_t data_len; 
} msg_header_t;

inline uint16_t hton_uint16(void * target, uint16_t value);

inline uint16_t ntoh_uint16(void * source);


#endif /* __MESSAGES_H__ */
