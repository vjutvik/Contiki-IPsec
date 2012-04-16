#include <string.h>
#include <stdlib.h>

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
const uip_ip6addr_t *my_ip_addr = &((struct uip_ip_hdr *) &uip_buf[UIP_LLH_LEN])->destipaddr;
const uip_ip6addr_t *peer_ip_addr = &((struct uip_ip_hdr *) &uip_buf[UIP_LLH_LEN])->srcipaddr;

extern uint16_t uip_slen;

// State machine declaration
// IKE_STATEM_DECLARE_STATEFN(name, type)
// ike_statem_statefn_ret_t ike_statem_##name##_##type##(ike_statem_session_t *session)

// Function declarations for providing hints to code in the upper parts of this file
void ike_statem_send(ike_statem_session_t *session, uint16_t len);
void ike_statem_timeout_handler(void *session);

/**
  * To be called in order to enter a _state_ (not execute a transition!)
  */
#define IKE_STATEM_ENTERSTATE(session)                                \
  /* Stop retransmission timer (if any has been set) */               \
  PRINTF(IPSEC_IKE "Session %p is entering state %p\n", (session), (session)->next_state_fn);  \
  STOP_RETRANSTIMER((session));                                       \
  if ((*(session)->next_state_fn)(session) == 0) {                    \
    PRINTF(IPSEC_IKE "Removing IKE session %p due to termination in state %p\n", session, (session)->next_state_fn);  \
    ike_statem_remove_session(session);                               \
  }                                                                   \
  return

#define SET_RETRANSTIMER(session) \
  ctimer_set(&session->retrans_timer, IKE_STATEM_TIMEOUT, &ike_statem_timeout_handler, (void *) session);
#define STOP_RETRANSTIMER(session) ctimer_stop(&(session)->retrans_timer)

#define SA_INDEX(arg) arg - 1

/**
  * Executes a state transition, moving from one state to another and sends a
  * an IKE message in the process
  */
void ike_statem_transition(ike_statem_session_t *session)
{
  PRINTF(IPSEC_IKE "Entering transition fn %p of session %p\n", (session)->transition_fn, session);  \

  msg_buf = (uint8_t *) udp_buf;                                   
  uint16_t len = (*(session)->transition_fn)((session));           
  /* send udp pkt here (len = start_ptr - udp_buf) */              
  PRINTF(IPSEC_IKE "Sending UDP packet of length %u\n", len);      
  /* MEMPRINTF("SENDING", msg_buf, len); */                        
  ike_statem_send((session), len);                                 
  SET_RETRANSTIMER((session));                                     
  return;
}



/**
  * Next free value for IKE SPI allocation. To be incremented upon creation of a new IKE SA.
  */
//uint16_t next_my_spi;

// Initialize the state machine
void ike_statem_init()
{
  list_init(sessions);
  srand(clock_time());
  //next_my_spi = rand16() & ~IKE_STATEM_MYSPI_I_MASK;
  
  // Set up the UDP port for incoming traffic
  printf("ike_statem_init: calling udp_new\n");
  my_conn = udp_new(NULL, UIP_HTONS(0), NULL);
  udp_bind(my_conn, UIP_HTONS(IKE_UDP_PORT)); // This will set lport to IKE_UDP_PORT
  PRINTF(IPSEC_IKE "State machine initialized. Listening on UDP port %d.\n", uip_ntohs(my_conn->lport));
  

  /*
  // Set up the UDP port for outgoing traffic
  tmit_conn = udp_new(remote, UIP_HTONS(IKE_UDP_PORT), NULL);
  udp_bind(tmit_conn, UIP_HTONS(3001));
  */
}

ike_statem_session_t *ike_statem_session_init()
{
  ike_statem_session_t *session = malloc(sizeof(ike_statem_session_t));
  PRINTF(IPSEC_IKE "Initiating IKE session %p\n", session);
  list_push(sessions, session);

  // Set the SPIs.
  session->peer_spi_high = IKE_MSG_ZERO;
  session->peer_spi_low = IKE_MSG_ZERO;
  IKE_STATEM_MYSPI_SET_NEXT(session->initiator_and_my_spi);

  session->my_msg_id = session->peer_msg_id = 0;

  // malloc() will do as this memory will soon be freed and thus won't clog up the heap for long.
  session->ephemeral_info = malloc(sizeof(ike_statem_ephemeral_info_t));

  // This random seed will be used for generating our nonce
  session->ephemeral_info->my_nonce_seed = rand16();
   
  /**
    * Generate the private key
    *
    * We're not interested in reusing the DH exponentials across sessions ("2.12.  Reuse of Diffie-Hellman Exponentials")
    * as the author finds the cost of storing them in memory exceeding the cost of the computation.
    */
  ecc_gen_private_key(session->ephemeral_info->my_prv_key);

  return session;
}


void ike_statem_setup_responder_session()
{
  ike_statem_session_t *session = ike_statem_session_init();

  // We're the responder
  IKE_STATEM_MYSPI_SET_R(session->initiator_and_my_spi);

  memcpy(&session->peer, peer_ip_addr, sizeof(uip_ip6addr_t));

  // Transition to state initrespwait
  session->next_state_fn = &ike_statem_state_parse_initreq;

  IKE_STATEM_ENTERSTATE(session);
}


/**
  * Initializes an new IKE session with the purpose of creating an SA in response to triggering_pkt_addr
  * and commanding_entry
  */
void ike_statem_setup_initiator_session(ipsec_addr_t *triggering_pkt_addr, spd_entry_t *commanding_entry)
{
  ike_statem_session_t *session = ike_statem_session_init();
  
  // Populate the session entry
  memcpy(&session->peer, triggering_pkt_addr->addr, sizeof(uip_ip6addr_t));
  
  // We're the initiator
  IKE_STATEM_MYSPI_SET_I(session->initiator_and_my_spi);
  
  // Transition to state initrespwait
  session->transition_fn = &ike_statem_trans_initreq;
  session->next_state_fn = &ike_statem_state_initrespwait;
  
  // Populate the ephemeral information with connection setup information  
  memcpy((void *) &session->ephemeral_info->triggering_pkt, (void *) triggering_pkt_addr, sizeof(ipsec_addr_t));
  session->ephemeral_info->triggering_pkt.addr = &session->peer;

  session->ephemeral_info->spd_entry = commanding_entry;

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
  PRINTF(IPSEC_IKE "Timeout for session %p. Reissuing last transition.\n", session);
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
    ike_statem_setup_responder_session();
    return;
  }
  
  // So, the request is concerns an existing session. Find the session struct by matching the SPIs.
  uint32_t my_spi = 0;
  if (IKE_PAYLOADFIELD_IKEHDR_FLAGS_INITIATOR & ike_hdr->flags) {
    // The other party is the original initiator
    my_spi = uip_ntohl(ike_hdr->sa_responder_spi_low);
  }
  else {
    // The other party is the responder
    my_spi = uip_ntohl(ike_hdr->sa_initiator_spi_low);
  }

  PRINTF(IPSEC_IKE "Handling incoming request concerning local IKE SPI %u\n", my_spi);

  ike_statem_session_t *session = NULL;
  PRINTF("my_spi: %u\n", my_spi);
  for (session = list_head(sessions); 
        session != NULL && !IKE_STATEM_MYSPI_GET_MYSPI(session) == my_spi; 
        session = list_item_next(session))
    PRINTF("SPI in list: %u\n", IKE_STATEM_MYSPI_GET_MYSPI(session));

  if (session != NULL) {
    // We've found the session struct of the session that the message concerns
      
    // Assert that the message ID is correct
    if (IKE_PAYLOADFIELD_IKEHDR_FLAGS_RESPONDER & ike_hdr->flags) {
      // It's response to something we sent. Does it have the right message ID?
      if (uip_ntohl(ike_hdr->message_id) != session->my_msg_id) {
        PRINTF(IPSEC_IKE_ERROR "Message ID is out of order. Dropping it.\n");
        return;
      }
    }
    else {  
      // It's a request
      if (uip_ntohl(ike_hdr->message_id) != session->peer_msg_id) {
        PRINTF(IPSEC_IKE_ERROR "Message ID is out of order. Dropping it.\n");
        return;
      }
      
      ++session->peer_msg_id;
    }
    
    IKE_STATEM_ENTERSTATE(session);
  }
  else {
    PRINTF(IPSEC_IKE_ERROR "We didn't find the session.\n");
    /**
      * Don't send any notification.
      * We're not sending any Notification regarding this dropped message. 
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
  //udp_bind(my_conn, UIP_HTONS(IKE_UDP_PORT)); // This will set lport to IKE_UDP_PORT
  
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
  //udp_bind(my_conn, UIP_HTONS(IKE_UDP_PORT));
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
  


