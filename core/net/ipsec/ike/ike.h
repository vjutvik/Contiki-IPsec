#include "machine.h"

extern process_event_t ike_negotiate_event;

void ike_init(void);

PROCESS_NAME(ike2_service);

/**
  * Call this to setup a child SA with traffic selectors matching triggering_pkt_addr and commanding_entry.
  */
ike_statem_session_t *ike_setup_session(ipsec_addr_t * triggering_pkt_addr, spd_entry_t * commanding_entry);
