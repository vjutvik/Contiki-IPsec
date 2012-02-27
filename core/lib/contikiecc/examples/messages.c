#include "messages.h"

/*---------------------------------------------------------------------------*/
inline uint16_t 
hton_uint16(void * target, uint16_t value) 
{
  uint8_t *base = target;
  base[1] = value;
  base[0] = value >> 8;
  return value;
}
/*---------------------------------------------------------------------------*/
inline uint16_t 
ntoh_uint16(void * source)
{
  uint8_t *base = source;
  return (uint16_t)(base[0] << 8 | base[1]);
}
/*---------------------------------------------------------------------------*/

