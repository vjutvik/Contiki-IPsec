/**
 * \addtogroup ipsec
 * @{
 */

/**
 * \file
 *        IPsec and IKEv2 configuration
 * \author
 *        Simon Duquennoy <simonduq@sics.se>
 *				Vilhelm Jutvik <ville@imorgon.se>
 */

#ifndef __IPSEC_H__
#define __IPSEC_H__

#include <contiki-conf.h>
#include "net/uip.h"

#if WITH_CONF_IPSEC_AH
#define WITH_IPSEC_AH     WITH_CONF_IPSEC_AH
#else
#define WITH_IPSEC_AH     0
#endif

#if WITH_CONF_IPSEC_ESP
#define WITH_IPSEC_ESP     WITH_CONF_IPSEC_ESP
#else
#define WITH_IPSEC_ESP     0
#endif

#if WITH_CONF_IPSEC_IKE
#define WITH_IPSEC_IKE  1
#else
#define WITH_IPSEC_IKE  0
#endif

#define WITH_IPSEC    (WITH_IPSEC_ESP | WITH_IPSEC_AH)


#define IPSEC_KEYSIZE_FIXTHIS   16  // Old bad code. Make the key size dynamic.
/*
#define IPSEC_IVSIZE    8
*/

/**
  * Debbugging for IKEv2 and IPsec
  */
#define IKE "IKEv2: "
#define IPSEC "IPsec: "
#define IPSEC_ERROR "IPsec error: "

/**
	* IPsec / IKEv2 debug configuration options are set here!
	*
	* There are more debuging options in uip6.c
	*/
#define DEBUG 1

#if DEBUG
#include <stdio.h>
#define PRINTF(...) printf(__VA_ARGS__)
#define PRINT6ADDR(addr) PRINTF(" %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x ", ((uint8_t *)addr)[0], ((uint8_t *)addr)[1], ((uint8_t *)addr)[2], ((uint8_t *)addr)[3], ((uint8_t *)addr)[4], ((uint8_t *)addr)[5], ((uint8_t *)addr)[6], ((uint8_t *)addr)[7], ((uint8_t *)addr)[8], ((uint8_t *)addr)[9], ((uint8_t *)addr)[10], ((uint8_t *)addr)[11], ((uint8_t *)addr)[12], ((uint8_t *)addr)[13], ((uint8_t *)addr)[14], ((uint8_t *)addr)[15])
#define PRINTLLADDR(lladdr) PRINTF(" %02x:%02x:%02x:%02x:%02x:%02x ",lladdr->addr[0], lladdr->addr[1], lladdr->addr[2], lladdr->addr[3],lladdr->addr[4], lladdr->addr[5])
#define IPSEC_MEM_STATS 1 
#define IPSEC_TIME_STATS 1
#else
#define IPSEC_MEM_STATS 0
#define IPSEC_TIME_STATS 0
#define PRINTF(...)
#define PRINT6ADDR(addr)
#endif

/* End debug configuration options */

/**
  * The length (in bytes) of the ICV field in the ESP header and that of IKEv2's SK payload.
  *
  * The length of this field is in fact dependent upon the integrity transform, but as most IKEv2 / IPsec
  * transforms uses the below length I figure that it's safe to make it static.
  */
#define IPSEC_ICVLEN   12

#define UIP_PROTO_ESP   50
#define UIP_PROTO_AH    51

#define UIP_ESP_BUF ((struct uip_esp_header *)&uip_buf[uip_l2_l3_hdr_len])

/* ESP header as defined in RFC 2406 */
struct uip_esp_header {
  uint32_t          spi;
  uint32_t          seqno;
  /**
    * IV and the data will now follow. These are both of variable length.

  unsigned char     iv[IPSEC_IVSIZE];
  unsigned char     data[0];
  */
};

/* The length of extension headers data coming after the payload */
extern uint8_t uip_ext_end_len;


#endif /* __IPSEC_H__ */
/** @} */
