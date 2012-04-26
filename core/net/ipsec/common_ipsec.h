#ifndef __COMMON_IPSEC_H__
#define __COMMON_IPSEC_H__

#include <limits.h>
#include "net/uip.h"
#include "ipsec.h"
#include "ike/payload.h"

/**
  * Debug stuff
  */

#if DEBUG
#define PRINTF(...) printf(__VA_ARGS__)

#define MEMPRINTF(str, ptr, len) \
  do {                    \
    printf(str  " (len %u):\n", len);          \
    memprint(ptr, len);   \
  } while(0);

// Only used in this file's scope
#define PRINTDIR(dir)                                   \
  uint8_t str[3][9] = {                                    \
    { "INCOMING" },                                     \
    { "OUTGOING" },                                     \
    { "ANY" }                                           \
  };                                                    \
  PRINTF("\ndirection: %s\n", str[dir])

// Prints the contents of an ipsec_addr_t variable at the given address
#define PRINTADDR(addr)                                             \
  do {                                                              \
    PRINT6ADDR((addr)->peer_addr);                                  \
    PRINTF("\nNextlayer proto: %hhu\n", (addr)->nextlayer_proto);     \
    PRINTF("My port: %hu\n", (addr)->my_port);                      \
    PRINTF("Peer port: %hu\n", (addr)->peer_port);                  \
  } while(0)

// Prints the contents of an ipsec_addr_set_t located at the given address
#define PRINTADDRSET(addr_set)                                                                \
  do {                                                                                        \
    PRINT6ADDR((addr_set)->peer_addr_from);                                                   \
    PRINT6ADDR((addr_set)->peer_addr_to);                                                     \
    PRINTF("\nNextlayer proto: %hhu\n", (addr_set)->nextlayer_proto);                         \
    PRINTF("My ports: %hu - %hu\n", (addr_set)->my_port_from, (addr_set)->my_port_to);        \
    PRINTF("Peer ports: %hu - %hu\n", (addr_set)->peer_port_from, (addr_set)->peer_port_to);  \
  } while(0)

#else
#define MEMPRINTF(...)
#define PRINTF(...)
#define PRINTADDR(...)
#define PRINTADDRSET(...)

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
  * The peer_addr_from field is a pointer to an IPv6 address that marks the beginning of a closed address range,
  * peer_addr_to marks its end. This address range is coupled to a packet's source address if it's incoming traffic,
  * its destination address otherwise.
  * 
  * peer_port_from represents the beginning of a closed range of ports, peer_port_to its end. This always represents the
  * destination port, irrespective of the traffic being outgoing or incoming.
  *
  * nextlayer_proto is the next layer protocol's type.
  *
  * Byte order
  * =====================
  * Addresses are stored in network byte order. Ports are stored in host byte order.
  */
typedef struct {
  uip_ip6addr_t *peer_addr_from, *peer_addr_to;

  /**
    * Next layer protocol type. 
    * Uses the next header values defined in uip.h (8 bits)
    *
    * A value of SPD_SELECTOR_NL_ANY_PROTOCOL is magic and should be interpreted as ANY protocol.
    */
  uint8_t nextlayer_proto; // Type of next layer protocol
  
//  direction_t direction;

  uint16_t my_port_from, my_port_to;      // Next layer destination port range
  uint16_t peer_port_from, peer_port_to;  // Next layer destination port range
} ipsec_addr_set_t;


/**
  * Packet information structure. Simmilary to ipsec_addr_set_t above, but for a single address rather than a set.
  *
  * addr points to the source address if the packet is inbound, destination address if outbound.
  * dest_port is always the destination port.
  *
  * Byte order
  * =====================
  * Addresses are stored in network byte order. Ports are stored in host byte order.
  */
typedef struct {
  uip_ip6addr_t *peer_addr;
//  direction_t direction;
  uint8_t nextlayer_proto;
  uint16_t my_port;
  uint16_t peer_port;
} ipsec_addr_t;


/**
  * Traffic descriptors are used in SAD entries
  * to describe the source (SAs for incoming traffic)
  * or destination (SAs for outgoing traffic) of traffic flows.
  */
/*
typedef struct {
  uip_ip6addr_t peer_addr;
  uint8_t nextlayer_proto;
  uint16_t port_from;
  uint16_t port_to;
} ipsec_traffic_desc_t;
*/

// Please note that the following next header value can be interpreted as "IPv6 Hop-by-Hop Option".
// We choose 0 anyway since it's the wildcard value used in the TS selector. Why RFC 5996 specifies
// that value and not the reserved value of 255 is interesting question.
// (Ref. IANA "Assigned Internet Protocol Numbers")
#define SPD_SELECTOR_NL_ANY_PROTOCOL IKE_PAYLOADFIELD_TS_NL_ANY_PROTOCOL

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
  (a) >= (b) && (a) <= (c)

extern uint8_t ipsec_a_is_member_of_b(ipsec_addr_t *a, ipsec_addr_set_t *b);
extern uint8_t uip6_addr_a_is_in_closed_interval_bc(uip_ip6addr_t *a, uip_ip6addr_t *b, uip_ip6addr_t *c);

#endif
