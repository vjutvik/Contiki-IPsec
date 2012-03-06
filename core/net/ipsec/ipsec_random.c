#include "contiki.h"
#include "random.h"

/**
  * Returns a random uint16_t
  */
uint16_t rand16(void)
{
  return (uint16_t) random_rand();
}

