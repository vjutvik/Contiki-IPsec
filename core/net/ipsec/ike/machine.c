#include "common_ike.h"
#include "machine.h"
#include "payload.h"
#include "ike.h"
#include "list.h"
#include "sys/ctimer.h"
#include "uip.h"
#include "string.h"

/**
  * IKEv2's behaviour is implemented as a mealy machine. These are its states:
  *
  *
  * Cost of using memory pointers (16 bit pointers):
  *   4 B * session_count   # References for current and past state (RAM)
  *   4 B * state_count     # With the assumption that each state references two other states, on average (ROM)
  *
  * Cost of using enums (8 bit enums, 16 bit pointers):
  *   4 B * session_count   # State id and state 
  *   2 B * state_count     # With the assumption that each state references two other states, on average
  */
/*
typedef enum {
  IKE_MSTATE_RESPOND_START,
  IKE_MSTATE_INITITATE_START,
  IKE_MSTATE_STARTNETTRAFFIC
  ...
} ike_statem_state_t;
*/

// Initialize the session table
LIST(sessions);

// Network stuff
static const uint8_t *udp_buf = &uip_buf[UIP_LLH_LEN + UIP_IPUDPH_LEN];
uint8_t *msg_buf;
static struct uip_udp_conn *my_conn;
extern uint16_t uip_slen;

// State machine declaration
// IKE_STATEM_DECLARE_STATEFN(name, type)
// ike_statem_statefn_ret_t ike_statem_##name##_##type##(ike_statem_session_t *session)

// Function declarations for providing hints to code in the upper parts of this file
void ike_statem_send(ike_statem_session_t *session, uint16_t len);
void ike_statem_timeout_handler(void *session);

/**
  * Call this macro when you want to execute a state transition 
  * (i.e. send a request / response).
  *
  * Can either be called from a state or from ike_statem_timeout_handler()
  */
#define IKE_STATEM_TRANSITION(session) \
  do {                                                    \
    msg_buf = (uint8_t *) udp_buf;                        \
    uint16_t len = (*(session)->transition_fn)((session));  \
    /* send udp pkt here (len = start_ptr - udp_buf) */   \
    ike_statem_send((session), len);                      \
    SET_RETRANSTIMER((session));                          \
  } while(0);                                             \
  return

/**
  * To be called in order to enter a _state_ (not execute a transition!)
  */
#define IKE_STATEM_ENTERSTATE(session)  \
  /* Stop retransmission timer (if any has been set) */ \
  STOP_RETRANSTIMER((session));         \
  (*(session)->next_state_fn)(session); \
  return

#define IKE_STATEM_INCRMYMSGID(session) ++session->my_msg_id;

#define SET_RETRANSTIMER(session) \
  ctimer_set(&session->retrans_timer, IKE_STATEM_TIMEOUT, &ike_statem_timeout_handler, (void *) session);
#define STOP_RETRANSTIMER(session) ctimer_stop(&(session)->retrans_timer)

#define SA_INDEX(arg) arg - 1


/**
  * Next free value for SPI allocation. To be incremented upon creation of a new IKE SA.
  */
uint16_t next_my_spi;

// Initialize the state machine
void ike_statem_init()
{
  list_init(sessions);
  next_my_spi = 1;
  
  // Set up the UDP port for incoming traffic
  my_conn = udp_new(NULL, UIP_HTONS(IKE_UDP_PORT), NULL);
  udp_bind(my_conn, UIP_HTONS(IKE_UDP_PORT)); // This will set lport to IKE_UDP_PORT
    
  /*
  // Set up the UDP port for outgoing traffic
  tmit_conn = udp_new(remote, UIP_HTONS(IKE_UDP_PORT), NULL);
  udp_bind(tmit_conn, UIP_HTONS(3001));
  */
}

/**
  * Initializes an new IKE session with the purpose of creating an SA in response to triggering_pkt_addr
  * and commanding_entry
  */
void ike_statem_setup_session(ipsec_addr_t *triggering_pkt_addr, spd_entry_t *commanding_entry)
{
  ike_statem_session_t *session = malloc(sizeof(session));
  list_push(sessions, session);
  
  // Populate the session entry
  memcpy(&session->peer, triggering_pkt_addr->addr, sizeof(*triggering_pkt_addr->addr));
  
  // Set the SPIs. We're the initiator.
  session->peer_spi_high = IKE_MSG_ZERO;
  session->peer_spi_low = IKE_MSG_ZERO;
  IKE_STATEM_MYSPI_SET_I(session->initiator_and_my_spi);
  IKE_STATEM_MYSPI_SET_NEXT(session->initiator_and_my_spi);
  
  session->my_msg_id = session->peer_msg_id = 0;
  
  // Transition to state initrespwait
  session->transition_fn = &ike_statem_trans_initreq;
  //session->next_state_fn = &ike_statem_state_initrespwait; // FIX: disabled
  
  // Populate the ephemeral information with connection setup information
  
  // malloc() will do as this memory will soon be freed and thus won't clog up the heap for long.
  session->ephemeral_info = malloc(sizeof(ike_statem_ephemeral_info_t));
  memcpy((void *) &session->ephemeral_info->triggering_pkt, (void *) triggering_pkt_addr, sizeof(*triggering_pkt_addr));
  session->ephemeral_info->spd_entry = commanding_entry;
  session->ephemeral_info->my_nonce_seed = rand16(); // This random seed will be used for generating our nonce
   
  /**
    * Generate the private key
    *
    * We're not interested in reusing the DH exponentials ("2.12.  Reuse of Diffie-Hellman Exponentials")
    * as the cost of storing them in memory exceeds the cost of the computation. (Source: the author, right now)
    */
  ecc_gen_private_key(session->ephemeral_info->my_prv_key);

  IKE_STATEM_TRANSITION(session);
}

void ike_statem_remove_session(ike_statem_session_t *session)
{
  STOP_RETRANSTIMER(session);   // It might be active, producing accidential transmissions
  list_remove(sessions, session);
}


/**
  * Timeout handler for state transitions (i.e. UDP messages that go unanswered)
  */
void ike_statem_timeout_handler(void *session)  // Void argument since we're called by ctimer
{
  IKE_STATEM_TRANSITION((ike_statem_session_t *) session);
}


/**
  * Traverses the list sessions, starting at head, returning the address of the first
  * entry with matching IPv6 address.
  *
  * \parameter addr Sought IPv6 address
  */
ike_statem_session_t *ike_statem_get_session_by_addr(uip_ip6addr_t *addr)
{
  ike_statem_session_t *session;
  
  for (session = list_head(sessions);
      session != NULL;
      session = list_item_next(session)) {
    uint8_t i;
    for(i = 0; i < sizeof(uip_ip6addr_t); ++i) {
      if(memcmp((const void *) &session->peer, (const void *) addr, sizeof(uip_ip6addr_t)) == 0)
        return session;
    }
  }

  return NULL;
}

/**
  * Get a session by the initiator's SPI
  */
/*
ike_statem_session_t *ike_statem_find_session(uint32_t initiator_spi) {
  ike_statem_session_t *session;
  for (session = list_head(sessions); 
        session != NULL && session->initiator_spi != initiator_spi; 
        session = list_item_next(session))
    ;
  return session;
}
*/



/**
  * Handler for incoming UDP traffic. Matches the data with the correct session (state machine)
  * using the IKE header.
  */
  

void ike_statem_incoming_data_handler()//uint32_t *start, uint16_t len)
{
  // Get the IKEv2 header
  ike_payload_ike_hdr_t *ike_hdr = (ike_payload_ike_hdr_t *) udp_buf;
  
  /**
    * The message that we've received is sent with the purpose of establishing
    * a new session or request something in relation to an existing one.
    *
    * We only regard the lower 32 bits of the IKE SPIs because I think it'll be enough to
    * distinguish them
    */  
  if (ike_hdr->sa_responder_spi_low == 0 && IKE_PAYLOADFIELD_IKEHDR_FLAGS_INITIATOR & ike_hdr->flags) {
    // The purpose of this request is to setup a new IKE session.
    // Don't write this code right now
    PRINTF(IPSEC_IKE "Handling incoming request for a new IKE session\n");
    ike_statem_state_respond_start();
  }
  
  // So, the request is concerns an existing session. Find the session struct by matching the SPIs.
  uint32_t *my_spi;
  if (IKE_PAYLOADFIELD_IKEHDR_FLAGS_INITIATOR & ike_hdr->flags) {
    // The other party is the original initiator
    my_spi = &ike_hdr->sa_responder_spi_low;
  }
  else {
    // The other party is the responder
    my_spi = &ike_hdr->sa_initiator_spi_low;    
  }

  PRINTF(IPSEC_IKE "Handling incoming request concerning local IKE SPI %lu\n", my_spi);

  ike_statem_session_t *session;
  for (session = list_head(sessions); 
        session != NULL && !IKE_STATEM_MYSPI_GET_MYSPI(session) == *my_spi; 
        session = list_item_next(session))
    ;

  if (session != NULL) {
    // We've found the session struct of the session that the message concerns
      
    // Assert that the message ID is correct
    if (IKE_PAYLOADFIELD_IKEHDR_FLAGS_RESPONDER & ike_hdr->flags) {
      // It's response to something we sent. Does it have the right message ID?
      if (ike_hdr->message_id != session->my_msg_id) {
        PRINTF(IPSEC "Error: Dropping message\n");
        return;
      }
    }
    else {  
      // It's a request
      if (ike_hdr->message_id != session->peer_msg_id + 1) {
        PRINTF(IPSEC "Error: Dropping message\n");
        return;
      }
      
      ++session->peer_msg_id;
    }
    
    IKE_STATEM_ENTERSTATE(session);
  }
  else {
    PRINTF(IPSEC "Error: We didn't find the session.\n");
    /**
      * Don't send any notification.
      * We're not sending any Notification regarind this dropped message. 
      * See section 1.5 "Informational Messages outside of an IKE SA" for more information.
      */
  }
}

/**
  * Send an UDP packet with the data currently stored in udp_buf (length derived from len)
  * to IP address session->peer
  */
void ike_statem_send(ike_statem_session_t *session, uint16_t len)
{
  uip_ipaddr_copy(&my_conn->ripaddr, &session->peer);
  my_conn->rport = UIP_HTONS(IKE_UDP_PORT);
  
  /**
    * By not using uip_udp_packet_send() and reimplementing the send code ourselves
    * The following code copies the behaviour of uip_udp_packet_send(),
    * with the exception of the memcpy() operation.
    */
  uip_udp_conn = my_conn;
  uip_slen = len;
  uip_process(UIP_UDP_SEND_CONN);
  tcpip_ipv6_output();

  // Reset everything so that we can listen to new packets
  uip_slen = 0;
  my_conn->rport = 0;
  uip_create_unspecified(&my_conn->ripaddr);
}

/**
  * This array maps state functions to state identifiers
  *
  */
/*static const ike_statem_statefn_args_t statefns[] = 
{
  
};
*/

/**
  * This data structure encodes the edges of the machine.
  */
/*
static const ike_statem_transition_t transitions[] = {
  {
    .edge = { .fromto[0] = IKE_MSTATE_START, .fromto[1] = IKE_MSTATE_INIT },
    ._do = &ike_m_initreply_do,
    .undo = &ike_m_initreply_undo
  },
  {
    
  }
};
*/


/**
  * States (nodes) for the session initiater machine
  */
  


