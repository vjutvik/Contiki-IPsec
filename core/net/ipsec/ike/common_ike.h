#ifndef __COMMON_IKE_H__
#define __COMMON_IKE_H__

#include <string.h>
#include "uip.h"
#include "ipsec.h"
#include "machine.h"
#include "payload.h"

extern void ike_statem_write_notification(payload_arg_t *payload_arg, 
                                sa_ipsec_proto_type_t proto_id,
                                uint32_t spi, 
                                notify_msg_type_t type, 
                                uint8_t *notify_payload, 
                                uint8_t notify_payload_len);
extern void ike_statem_set_id_payload(payload_arg_t *payload_arg, ike_payload_type_t payload_type);
extern void ike_statem_write_sa_payload(payload_arg_t *payload_arg, spd_proposal_tuple_t *offer, uint32_t spi);
extern void ike_statem_get_keymat(ike_statem_session_t *session, uint8_t *peer_pub_key);
extern void ike_statem_transition(ike_statem_session_t *session);
extern int8_t ike_statem_parse_sa_payload(spd_proposal_tuple_t *my_offer, 
                                ike_payload_generic_hdr_t *sa_payload_hdr, 
                                uint8_t ke_dh_group,
                                sa_ike_t *ike_sa,
                                sa_child_t *child_sa,
                                spd_proposal_tuple_t *accepted_transform_subset);
extern uint16_t ike_statem_get_authdata(ike_statem_session_t *session,
                                        uint8_t myauth, 
                                        uint8_t *out, 
                                        ike_id_payload_t *id_payload, 
                                        uint16_t id_payload_len);
extern void ike_statem_finalize_sk(payload_arg_t *payload_arg, 
                                        ike_payload_generic_hdr_t *sk_genpayloadhdr, 
                                        uint16_t data_len);
extern u8_t ike_statem_unpack_sk(ike_statem_session_t *session, ike_payload_generic_hdr_t *sk_genpayloadhdr);
extern void ike_statem_prepare_sk(payload_arg_t *payload_arg);

#define IPSEC_IKE "IPsec IKEv2: "
#define IPSEC_IKE_ERROR "IPsec IKEv2: Error: "

#define IKE_STATEM_ASSERT_COOKIE(payload_arg)                                                         \
  do {                                                                                                \
    if (payload_arg->session->cookie_payload != NULL) {                  \
      ike_payload_generic_hdr_t *genpayload_hdr = (ike_payload_generic_hdr_t *) (payload_arg)->start; \
      uint8_t offset = sizeof(genpayload_hdr) + sizeof(ike_payload_notify_t);                         \
      uint8_t *cookie_data = genpayload_hdr + offset;                                                 \
      uint8_t cookie_data_len = UIP_NTOHS(genpayload_hdr->len) - offset;                              \
      ike_statem_write_notification((payload_arg),                                                    \
        SA_PROTO_IKE,                                                                                 \
        0,                                                                                            \
        IKE_PAYLOAD_NOTIFY_COOKIE,                                                                    \
        cookie_data,                                                                                  \
        cookie_data_len));                                                                            \
    }                                                                                                \
  } while(false);
  
  
/**
  * Copies a complete IKE message to the session_ptr's ephemeral_info. Used for authentication.
  */
#define COPY_FIRST_MSG(session_ptr, ike_hdr_ptr)                                            \
  do {                                                                                      \
    uint32_t len = uip_ntohl(ike_hdr_ptr->len);                                             \
    if (len > IKE_STATEM_FIRSTMSG_MAXLEN) {                                                 \
      /* Error: Responder's first message is too big  */                                    \
      PRINTF(IPSEC_IKE " Reponder's first message is too big\n");                           \
      return 0;                                                                               \
    }                                                                                       \
    else {                                                                                  \
      session_ptr->ephemeral_info->peer_first_msg_len = (uint16_t) len;                     \
      memcpy(&session_ptr->ephemeral_info->peer_first_msg, ike_hdr_ptr, len);               \
    }                                                                                       \
  }                                                                                         \
  while (0)
  
#endif
