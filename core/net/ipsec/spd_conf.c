/**
  * This file contains functions for SPD configuration.
  *
  * All values and definitions described herein pertains to RFC 4301 (Security Architecture for IP) and
  * RFC 5996 (Internet Key Exchange Protocol Version 2). Sections of special interests are:
  *
  * RFC 4301: 4.4.1 (Security Policy Database)
  * RFC 5996: 3.3 (Security Association Payload)
  *
  * Please see spd.h for a quick overview of the data format.
  */

#include "sa.h"
#include "spd.h"
#include "uip.h"

//#define SPD_CONF_POLICY_ENTRIES_LEN 2

//#define uip_ip6addr_set_min(addr) memset(addr, 0, 16)
//#define uip_ip6addr_set_max(addr) memset(addr, 0xff, 16)


#define uip_ip6addr_set_val16(ip6addr, val) \
    ip6addr.u16[0] = val, \
    ip6addr.u16[1] = val, \
    ip6addr.u16[2] = val, \
    ip6addr.u16[3] = val, \
    ip6addr.u16[4] = val, \
    ip6addr.u16[5] = val, \
    ip6addr.u16[6] = val, \
    ip6addr.u16[7] = val

/*
#define uip_ip6addr_set_min(ip6addr) uip_ip6addr_set_val16(ip6addr, 0x0000)
#define uip_ip6addr_set_max(ip6addr) uip_ip6addr_set_val16(ip6addr, 0xffff)
*/

//const spd_table_t spd_table[SPD_CONF_POLICY_ENTRIES_LEN];

// Section "3.4.  Key Exchange Payload" specifies an interdependence between the IKE proposal's
// MODP group and the KE payload. The following define states this common property.
#define SA_IKE_MODP_GROUP SA_DH_192_RND_ECP_GROUP

/**
  * IKEv2 proposals as described in RFC 5996 with the following exceptions:
  *
  * > Every proposal must offer integrity protection. This is provided through a combined mode
  *   transform _or_ via the integrity dito.
  */
const spd_proposal_tuple_t spdconf_ike_proposal[] =
{
  // IKE proposal
  { SA_CTRL_NEW_PROPOSAL, SA_PROTO_IKE }, 
  { SA_CTRL_TRANSFORM_TYPE_ENCR, SA_ENCR_AES_CTR },
  { SA_CTRL_TRANSFORM_TYPE_INTEG, SA_INTEG_AES_XCBC_MAC_96 },
  { SA_CTRL_TRANSFORM_TYPE_DH, SA_IKE_MODP_GROUP },
  { SA_CTRL_TRANSFORM_TYPE_PRF, SA_PRF_HMAC_SHA1},
  // Terminate the offer
  { SA_CTRL_END_OF_OFFER, 0}
};

static const spd_proposal_tuple_t my_ah_esp_poposal[] = 
  { 
    // ESP proposal
    { SA_CTRL_NEW_PROPOSAL, SA_PROTO_ESP }, 
    { SA_CTRL_TRANSFORM_TYPE_ENCR, SA_ENCR_AES_CBC },
    { SA_CTRL_TRANSFORM_TYPE_ENCR, SA_ENCR_AES_CTR },
    { SA_CTRL_TRANSFORM_TYPE_INTEG, SA_INTEG_AES_XCBC_MAC_96 },

    // AH proposal
    { SA_CTRL_NEW_PROPOSAL, SA_PROTO_AH },
    { SA_CTRL_TRANSFORM_TYPE_INTEG, SA_INTEG_HMAC_SHA1_96 },
    
    // Terminate the offer
    { SA_CTRL_END_OF_OFFER, 0}
  };
/*
#define set_any_src_ip6addr \
  uip_ip6addr_set_min(.ip6addr_src_range_from), \
  uip_ip6addr_set_max(.ip6addr_src_range_to)

#define set_any_dst_ip6addr \
  uip_ip6addr_set_min(.ip6addr_dst_range_from), \
  uip_ip6addr_set_max(.ip6addr_dst_range_to)
*/


/**
  * Convenience preprocessor commands for creating the policy table
  */

#define set_ip6addr(direction, ip6addr)   \
  .ip6addr_##direction##_from = ip6addr,  \
  .ip6addr_##direction##_to = ip6addr

#define set_any_ip6addr() \
  .addr_from = &spd_conf_ip6addr_min,     \
  .addr_to = &spd_conf_ip6addr_max

/*
#define set_localhost_src_ip6addr \
  .ip6addr_src_range_from = &spd_conf_ip6addr_localhost,  \
  .ip6addr_src_range_to = &spd_conf_ip6addr_localhost

#define set_localhost_dst_ip6addr \
  .ip6addr_dst_range_from = &spd_conf_ip6addr_localhost,  \
  .ip6addr_dst_range_to = &spd_conf_ip6addr_localhost
*/


#define set_dest_port(port)                         \
  .dest_port_from = uip_htons(port),                \
  .dest_port_to = uip_htons(port)


#define set_any_dest_port()                         \
  .dest_port_from = 0U,                             \
  .dest_port_to = UIP_HTONS(PORT_MAX)

  
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
const spd_entry_t spd_table[SPD_ENTRIES] = 
  {
    // BYPASS for IKE traffic
    {
      .selector =
      {
        .direction = SPD_INCOMING_TRAFFIC,   // This concerns incoming traffic...
        set_any_ip6addr(),                  // ...from any host...
        //.nextlayer_type = UIP_PROTO_UDP,    // ...using UDP...
        .nextlayer_type = SPD_SELECTOR_NL_ANY_PROTOCOL,
        //set_dest_port(500)                  // ...on port 500.
        set_any_dest_port()
      },
      .proc_action = SPD_ACTION_BYPASS,     // No protection necessary
      .offer = NULL                         // N/A
    },
    
    /*
    // PROTECT outgoing UDP traffic on UDP port 1234 (for ipsec-example.sky)
    {
      .selector =
      {
        .direction = SPD_OUTGOING_TRAFFIC,
        set_any_ip6addr(),        
        .nextlayer_type = UIP_PROTO_UDP,
        //.nextlayer_type = SPD_SELECTOR_NL_ANY_PROTOCOL,
        set_src_port(1234),
        set_any_dest_port()
      },
      .proc_action = SPD_ACTION_PROTECT,     // No protection necessary
      .offer = NULL                         // N/A
    },
    */

    // BYPASS outgoing ICMP6 traffic
    {
      .selector =
      {
        .direction = SPD_OUTGOING_TRAFFIC,
        set_any_ip6addr(),        
        .nextlayer_type = UIP_PROTO_ICMP6,
        set_any_dest_port()
      },
      .proc_action = SPD_ACTION_BYPASS,     // No protection necessary
      .offer = NULL                         // N/A
    },
    
    // DISCARD all traffic which haven't matched any prior policy rule
    // All IPSec implementations SHOULD exhibit this behaviour (p. 60 RFC 4301)
    {
      .selector =
      {
        .direction = SPD_ANY_TRAFFIC,       // This concerns incoming as well as outgoing traffic
        set_any_ip6addr(),                  // Any source (incoming traffic), any destination (outgoing)        
        .nextlayer_type = SPD_SELECTOR_NL_ANY_PROTOCOL,
        set_any_dest_port()
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
  PRINTF("SPD_TABLE at %x\n", spd_table);
  uip_ip6addr_set_val16(spd_conf_ip6addr_min, 0x0);
  uip_ip6addr_set_val16(spd_conf_ip6addr_max, 0xffff);
  PRINTF("SPD_TABLE at %x\n", spd_table);
}
