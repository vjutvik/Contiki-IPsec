#ifndef __COMMON_IPSEC_H__
#define __COMMON_IPSEC_H__

#include <limits.h>
#include "net/uip.h"
#include "ipsec.h"

/**
  * Debug stuff
  */

#ifdef DEBUG

// Only used in this file's scope
#define PRINTDIR(dir)                                   \
  uint8_t str[3][9] = {                                    \
    { "INCOMING" },                                     \
    { "OUTGOING" },                                     \
    { "ANY" }                                           \
  };                                                    \
  PRINTF("\ndirection: %s\n", str[dir])

// Prints the contents of an ipsec_addr_t variable at the given address
#define PRINTADDR(addr)                                   \
  do {                                                    \
    PRINT6ADDR((addr)->addr);                             \
    PRINTDIR((addr)->direction);                          \
    PRINTF("nl: %u\n", (addr)->nextlayer_type);           \
    PRINTF("dest_port: %u\n", uip_ntohs((addr)->dest_port));         \
  } while(0)

// Prints the contents of an ipsec_addr_set_t located at the given address
#define PRINTADDRSET(addr_set)                                    \
  do {                                                            \
    PRINT6ADDR((addr_set)->addr_from);                            \
    PRINT6ADDR((addr_set)->addr_to);                              \
    PRINTDIR((addr_set)->direction);                              \
    PRINTF("nl: %u\n", (addr_set)->nextlayer_type);             \
    PRINTF("Dest ports: %u - %u\n", uip_ntohs((addr_set)->dest_port_from), uip_ntohs((addr_set)->dest_port_to)); \
  } while(0)

#else

#define PRINTADDR
#define PRINTADDRSET

#endif

/**
  * Type used for denoting the direction of traffic.
  */
typedef enum {
  SPD_INCOMING_TRAFFIC,
  SPD_OUTGOING_TRAFFIC,
  SPD_ANY_TRAFFIC
} direction_t;


/**
  * Port ranges
  */
#define PORT_MAX USHRT_MAX


/**
  * The SPD selector specifies a set of IP packet properties (IP address, destination, port etc).
  *
  * Semantics
  * ====================
  * An ipsec_addr_set_t struct represents a set of incoming or outgoing traffic (or their union). Depending on the direction
  * of the traffic, the semantics of the fields differ.
  *
  * The addr_from field is a pointer to an IPv6 address that marks the beginning of a closed address range,
  * addr_to marks its end. This address range is coupled to a packet's source address if it's incoming traffic,
  * its destination address otherwise.
  * 
  * dest_port_from represents the beginning of a closed range of ports, dest_port_to its end. This always represents the
  * destination port, irrespective of the traffic being outgoing or incoming.
  *
  * nextlayer_type is the next layer protocol's type.
  *
  * Byte order
  * =====================
  * Addresses and ports are stored in network byte order.
  */
typedef struct {
  uip_ip6addr_t *addr_from, *addr_to;

  /**
    * Next layer protocol type. 
    * Uses the next header values defined in uip.h (8 bits)
    *
    * A value of SPD_SELECTOR_NL_ANY_PROTOCOL is magic and should be interpreted as ANY protocol.
    */
  uint8_t nextlayer_type; // Type of next layer protocol
  
  direction_t direction;

  uint16_t dest_port_from, dest_port_to; // Next layer destination port range
  // uint16_t nextlayer_dst_port_range_from, nextlayer_dst_port_range_to; 
} ipsec_addr_set_t;


/**
  * Packet information structure. Simmilary to ipsec_addr_set_t above, but for a single address rather than a set.
  *
  * addr points to the source address if the packet is inbound, destination address if outbound.
  * dest_port is always the destination port.
  *
  * Byte order
  * =====================
  * Addresses and ports are stored in network byte order.
  */
typedef struct {
  uip_ip6addr_t *addr;
  direction_t direction;
  uint8_t nextlayer_type;
  uint16_t dest_port;
} ipsec_addr_t;

// Please note that the following next header value can be interpreted as "IPv6 Hop-by-Hop Option".
// We choose 0 anyway since it's the wildcard value used in the TS selector. Why RFC 5996 specifies
// that value and not the reserved value of 255 is interesting question.
// (Ref. IANA "Assigned Internet Protocol Numbers")
#define SPD_SELECTOR_NL_ANY_PROTOCOL 0 


/**
  * Convenience macros for address comparison
  */
/*
#define uip6_addr_a_is_geq_than_b(a, b) \
  a->u16[0] >= b->u16[0] && \
  a->u16[1] >= b->u16[1] && \
  a->u16[2] >= b->u16[2] && \
  a->u16[3] >= b->u16[3] && \
  a->u16[4] >= b->u16[4] && \
  a->u16[5] >= b->u16[5] && \
  a->u16[6] >= b->u16[6] && \
  a->u16[7] >= b->u16[7]
*/
/*
#define uip6_addr_a_is_geq_than_b(a, b) \
  (a->u8[0] >= b->u8[0] && \
  a->u8[1] >= b->u8[1] && \
  a->u8[2] >= b->u8[2] && \
  a->u8[3] >= b->u8[3] && \
  a->u8[4] >= b->u8[4] && \
  a->u8[5] >= b->u8[5] && \
  a->u8[6] >= b->u8[6] && \
  a->u8[7] >= b->u8[7] && \
  a->u8[8] >= b->u8[8] && \
  a->u8[9] >= b->u8[9] && \
  a->u8[10] >= b->u8[10] && \
  a->u8[11] >= b->u8[11] && \
  a->u8[12] >= b->u8[12] && \
  a->u8[13] >= b->u8[13] && \
  a->u8[14] >= b->u8[14] && \
  a->u8[15] >= b->u8[15])*/


// #define uip6_addr_a_is_leq_than_b(a, b) uip6_addr_a_is_geq_than_b(b, a)

#define a_is_in_closed_interval_bc(a, b, c) \
  a >= b && a <= c

uint8_t ipsec_a_is_member_of_b(ipsec_addr_t *a, ipsec_addr_set_t *b);

#endif
