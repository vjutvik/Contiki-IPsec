/**
  * Convenience functions for writing IKE messages. You are encouraged to use these macros
  * as much as possible when manipulating IKE messages as they are (should be) platform
  * independent. This is especially true of multibyte stuff.
  *
  *
  *                   ! WARNING !
  * Carefully read the requirements of any macro that you intend to use!
  * Feeding it with the wrong type or making careless casts might cause undue effects.
  *
  */

#include "uip.h"
  

/**
  * Macros for packing IKE messages
  */

// Nice constants
#define IKE_MSG_ZERO 0x0 // The compiler will first try to fit hex-values into unsigned variables

// Returns a byte with all bits set to 0, except bit n (0-7)
//
// macro(n) -> unsigned integer. n is 0-7
#define IKE_MSG_GET_8BITMASK(n) (0x80 >> n)

// Clears all bits of any unsigned integer
//
// macro(unsigned integer) -> unsigned integer
#define IKS_MSG_CLEAR(val) val = 0x0 // The compiler will try to fit hexadecimal constants in unsigned integers first

// Write a one byte int to some position (0-3) in a 32 bit word
// macro(uint32_t *, uint8_t, uint8_t)
#define IKE_MSG_32WR8(ptr, pos, val) *((uint8_t *) ptr + pos) = val 

// Write a two byte int to lower or upper part of a 32 bit word, converting to network byte order
// macro(uint32_t *, uint8_t, uint16_t)
#define IKE_MSG_32WR16_HTON(ptr, upper, val) *((uint16_t *) ptr + upper) = UIP_HTONS(val)

// Write a four byte int to a 32 bit word, converting to network byte order
// macro(uint32_t *, uint8_t, uint8_t)
#define IKE_MSG_32WR32_HTON(ptr, val) *ptr = UIP_HTONL(val)


// ptr _must_ start at a 16-bit word boundary
#define IKE_MSG_WRITE16(ptr, n) *((uint16_t *) ptr) = UIP_HTONS(n)

// ptr _must_ start at a 32-bit word boundary
#define IKE_MSG_WRITE32(ptr, n) *((uint32_t *) ptr) = UIP_HTONL(n)
