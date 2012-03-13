#ifndef __IKE_H__
#define __IKE_H__

#include "contiki.h"
#include "process.h"

/**
  * Send this event to the ike2_service in order to trigger negotiation. Please see
  * process declaration for argument documentation.
  */
extern process_event_t ike_negotiate_event;

/**
  * Argument containing the address of the triggering packet
  */
extern ipsec_addr_t ike_arg_packet_tag;

PROCESS_NAME(ike2_service);

/**
  * Call this to initiate the IKEv2 service
  */
void ike_init(void);

#endif