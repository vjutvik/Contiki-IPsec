#include <string.h>
#include "ipsec.h"

#define IPSEC_IKE "IPsec IKEv2: "

#define IKE_STATEM_ASSERT_COOKIE(payload_arg) do { \
    if (payload_arg->session->ephemeral_info->cookie_data != NULL) { \
      ike_payload_generic_hdr_t *genpayload_hdr = (ike_payload_generic_hdr_t *) payload_arg->start; \
      uint8_t offset = sizeof(genpayload_hdr) + sizeof(ike_payload_notify_t); \
      uint8_t *cookie_data = genpayload_hdr + offset; \
      uint8_t cookie_data_len = UIP_NTOHS(genpayload_hdr->len) - offset; \
      ike_statem_write_notification(payload_arg, \
        SA_PROTO_IKE, \
        0, \
        IKE_PAYLOAD_NOTIFY_COOKIE, \
        cookie_data, \
        cookie_data_len)); \
    } \
  } while(false)
  
  
/**
  * Copies a complete IKE message to the session_ptr's ephemeral_info. Used for authentication.
  */
  /*
#define COPY_FIRST_MSG(session_ptr_ptr, ike_hdr_ptr_ptr)                                  \
  session_ptr->ephemeral_info->peer_first_msg_len = UIP_NTOHS(ike_hdr_ptr->len);          \
  if (session_ptr->ephemeral_info->peer_first_msg_len > IKE_STATEM_FIRSTMSG_MAXLEN) {     \
    // Error: Responder's first message is too big                                        \
    ike_statem_remove_session_ptr(session_ptr);                                           \
    return;                                                                               \
  }                                                                                       \
  else                                                                                    \
    memcpy(&session_ptr->ephemeral_info->peer_first_msg, ike_hdr_ptr, session_ptr->ephemeral_info->peer_first_msg_len)

*/
