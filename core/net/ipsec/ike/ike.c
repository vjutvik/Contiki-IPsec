#include "machine.h"
#include "ike.h"
#include "common_ipsec.h"
#include "common_ike.h"
#include "spd.h"

process_event_t ike_negotiate_event;

void ike_init()
{
  ike_negotiate_event = process_alloc_event();
  process_start(&ike2_service, NULL);
}


static void ike_negotiate_sa(ipsec_addr_t *triggering_pkt_addr, spd_entry_t *commanding_entry)
{
  /**
    * We're here because the outgoing packet associated with trigger_pkt_addr didn't find any SAD entry
    * with matching traffic selectors. The expected result of a call to this function is that the Child SA
    * is negotiated with the other peer and inserted into the SAD. Until that happens, traffic of this type 
    * is simply dropped.
    *
    * Search the session table for an IKE session where the remote peer's IP matches that of the triggering
    * packet's. If such is found, start at state 
    * ike_statem_state_common_createchildsa(session, addr_t triggering_pkt, spd_entry_t commanding_entry)
    * if busy, discard pkt
    *
    */

  /*
  ike_statem_session_t *session;
  if((session = ike_statem_get_session_by_addr(triggering_pkt_addr->addr)) != NULL) {
    // Command this session to create a new child SA
    if (IKE_STATEM_SESSION_ISREADY(session)) {
      PRINTF(IPSEC_IKE "Using existing IKE session for SA negotiation\n");
//      **
        * Cause the already established session to negotiate a new set of SAs. Disabled as for now.
//        *
      // Warn: Second negotiation attempt. Disabled
    }
    else
      PRINTF(IPSEC_IKE ": Warning: Couldn't create child SA in response to triggering packet since IKE session was busy\n");
  }
  else {*/
    // We don't have an IKE session with this host. Connect and setup.
    ike_statem_setup_session(triggering_pkt_addr, commanding_entry);
  //}
}


/**
  * IKEv2 protothread. Handles the events by which the service is controlled.
  *
  EVENTS
  
    TYPE: ike_negotiate_event
    DESCRIPTION: Initiates an IKEv2 negotiation with the destination host. Data points to a pointer array starting
                with a pointer to the triggering packet's address structure (type ipsec_addr_t *), followed by a pointer
                to the commanding SPD entry (spd_entry_t *).
  
    TYPE: tcpip_event
    DESCRIPTION: Dispatched by the uIP stack upon reception of new data. Data is undefined.
    
    (More to come? SAD operations likely)
  *
  */
PROCESS(ike2_service, "IKEv2 Service");
PROCESS_THREAD(ike2_service, ev, data)
{
  PROCESS_BEGIN();
  
  ike_statem_init();
  
  while(1) {
    PROCESS_WAIT_EVENT();
    if (ev == ike_negotiate_event)
      ike_negotiate_sa((ipsec_addr_t *) ((u8_t **) data)[0], (spd_entry_t *) ((u8_t **) data)[1]);
    else {
      if (ev == tcpip_event)
        ike_statem_incoming_data_handler();
      else
        PRINTF(IPSEC_IKE "ike2_service: Unknown event\n");
    }
  }
  
  PROCESS_END();
}
