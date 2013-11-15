/**
 * \addtogroup ipsec
 * @{
 */

/**
 	* \file
 	* 			SPD configuration
	*	\details
  * 			This file contains functions for SPD configuration.
  * 			
  * 			All values and definitions described herein pertains to RFC 4301 (Security Architecture for IP) and
  * 			RFC 5996 (Internet Key Exchange Protocol Version 2). Sections of special interests are:
  * 			
  * 			RFC 4301: 4.4.1 (Security Policy Database)
  * 			RFC 5996: 3.3 (Security Association Payload)
  * 			
  * 			Please see spd.h for a quick overview of the data format.
	* \author
 	*				Vilhelm Jutvik <ville@imorgon.se>
  */

/*
 * Copyright (c) 2012, Vilhelm Jutvik.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * This file is part of the Contiki operating system.
 */

#include "sa.h"
#include "spd.h"
#include "uip.h"
#include "spd_conf.h"


#define uip_ip6addr_set_val16(ip6addr, val) \
    ip6addr.u16[0] = val, \
    ip6addr.u16[1] = val, \
    ip6addr.u16[2] = val, \
    ip6addr.u16[3] = val, \
    ip6addr.u16[4] = val, \
    ip6addr.u16[5] = val, \
    ip6addr.u16[6] = val, \
    ip6addr.u16[7] = val


/**
  * IKEv2 proposals as described in RFC 5996 with the following exceptions:
  *
  * > Every proposal must offer integrity protection. This is provided through a combined mode
  *   transform _or_ via the integrity dito.
  */
const spd_proposal_tuple_t spdconf_ike_proposal[7] =
{
  // IKE proposal
  { SA_CTRL_NEW_PROPOSAL, SA_PROTO_IKE }, 
  { SA_CTRL_TRANSFORM_TYPE_ENCR, SA_ENCR_AES_CTR },
  { SA_CTRL_ATTRIBUTE_KEY_LEN,  16 },  /* Key len in _bytes_ (128 bits) */
  { SA_CTRL_TRANSFORM_TYPE_INTEG, SA_INTEG_AES_XCBC_MAC_96 },
  { SA_CTRL_TRANSFORM_TYPE_DH, SA_IKE_MODP_GROUP },
  { SA_CTRL_TRANSFORM_TYPE_PRF, SA_PRF_HMAC_SHA1},
  // Terminate the offer
  { SA_CTRL_END_OF_OFFER, 0}
};

const spd_proposal_tuple_t spdconf_ike_open_proposal[6] =
{
  // IKE proposal
  { SA_CTRL_NEW_PROPOSAL, SA_PROTO_IKE },
  { SA_CTRL_TRANSFORM_TYPE_ENCR, SA_ENCR_NULL },
  { SA_CTRL_TRANSFORM_TYPE_INTEG, SA_INTEG_AES_XCBC_MAC_96 },
  { SA_CTRL_TRANSFORM_TYPE_DH, SA_IKE_MODP_GROUP },
  { SA_CTRL_TRANSFORM_TYPE_PRF, SA_PRF_HMAC_SHA1},
  // Terminate the offer
  { SA_CTRL_END_OF_OFFER, 0}
};


const spd_proposal_tuple_t my_ah_esp_proposal[10] = 
{ 
  // ESP proposal
  { SA_CTRL_NEW_PROPOSAL, SA_PROTO_ESP}, 
  { SA_CTRL_TRANSFORM_TYPE_ENCR, SA_ENCR_NULL },
  { SA_CTRL_TRANSFORM_TYPE_ENCR, SA_ENCR_AES_CBC },
  { SA_CTRL_ATTRIBUTE_KEY_LEN,  16 },  /* Key len in _bytes_ (128 bits) */
  { SA_CTRL_TRANSFORM_TYPE_ENCR, SA_ENCR_AES_CTR },
  { SA_CTRL_ATTRIBUTE_KEY_LEN,  16 },  /* Key len in _bytes_ (128 bits) */
  { SA_CTRL_TRANSFORM_TYPE_INTEG, SA_INTEG_AES_XCBC_MAC_96 },

  // AH proposal
  { SA_CTRL_NEW_PROPOSAL, SA_PROTO_AH },
  { SA_CTRL_TRANSFORM_TYPE_INTEG, SA_INTEG_HMAC_SHA1_96 },
  
  // Terminate the offer
  { SA_CTRL_END_OF_OFFER, 0}
};


/**
  * Convenience preprocessor commands for creating the policy table
  */

#define set_ip6addr(direction, ip6addr)   \
  .ip6addr_##direction##_from = ip6addr,  \
  .ip6addr_##direction##_to = ip6addr

#define set_any_peer_ip6addr() \
  .peer_addr_from = &spd_conf_ip6addr_min,     \
  .peer_addr_to = &spd_conf_ip6addr_max



#define set_my_port(port)               \
  .my_port_from = port,                 \
  .my_port_to = port

#define set_any_my_port()               \
  .my_port_from = 0,                    \
  .my_port_to = PORT_MAX

#define set_peer_port(port)             \
  .peer_port_from = port,               \
  .peer_port_to = port

#define set_any_peer_port()             \
  .peer_port_from = 0,                  \
  .peer_port_to = PORT_MAX

  
/**
  * IP adresses that we use in policy rules.
  *
  * spd_conf_ip6addr_init() must be called prior to using the data structures in question
  */
uip_ip6addr_t spd_conf_ip6addr_min;       // Address ::
uip_ip6addr_t spd_conf_ip6addr_max;       // Address ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff


/**
  * Setup of the SPD. This is where you as the user enters the security policy of your system.
  *
  * Adjust SPD_ENTRIES (in spd.h) according to need.
  */
spd_entry_t spd_table[SPD_ENTRIES] = 
  {
    // BYPASS IKE traffic
    {
      .selector =
      {
        set_any_peer_ip6addr(),             // ...from any host...
        .nextlayer_proto = UIP_PROTO_UDP,   // ...using UDP...
        set_my_port(500),                  	// ...to destination port 500.
        set_any_peer_port()                 // ...from any source port
      },
      .proc_action = SPD_ACTION_BYPASS,     // No protection necessary
      .offer = NULL                         // N/A
    },
    
    // PROTECT all UDP traffic to host aaaa::1
    {
      .selector =
      {
        set_any_peer_ip6addr(),
        .nextlayer_proto = UIP_PROTO_UDP,
        //.nextlayer_proto = SPD_SELECTOR_NL_ANY_PROTOCOL,
        set_any_my_port(),
        set_any_peer_port()
      },
      .proc_action = SPD_ACTION_PROTECT,
#if WITH_IPSEC_IKE
      .offer = my_ah_esp_proposal
#else
			.offer = NULL
#endif
    },

    // BYPASS all ICMP6 traffic in order to make RPL auto configuration possible
    {
      .selector =
      {
        set_any_peer_ip6addr(),
        .nextlayer_proto = UIP_PROTO_ICMP6,
        set_any_my_port(),
        set_any_peer_port()
      },
      .proc_action = SPD_ACTION_BYPASS,     // No protection necessary
      .offer = NULL                         // N/A
    },
    
    // DISCARD all traffic which haven't matched any prior policy rule
    // All IPSec implementations SHOULD exhibit this behaviour (p. 60 RFC 4301)
    {
      .selector =
      {
        set_any_peer_ip6addr(),                  // Any source (incoming traffic), any destination (outgoing)        
        .nextlayer_proto = SPD_SELECTOR_NL_ANY_PROTOCOL,
        set_any_my_port(),
        set_any_peer_port()
      },
      .proc_action = SPD_ACTION_DISCARD,
      .offer = NULL
    }
  };


/**
  * Initializes the SPD
  *
  * \param localhost_ip6addr A pointer to the memory location of the local host's current IPv6 address. A copy of that memory area will be made.
  */
void spd_conf_init() {
  uip_ip6addr_set_val16(spd_conf_ip6addr_min, 0x0);
  uip_ip6addr_set_val16(spd_conf_ip6addr_max, 0xffff);
}

/** @} */
