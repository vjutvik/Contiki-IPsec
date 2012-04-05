#include <stdlib.h>
#include "sad.h"
#include "common_ike.h"
#include "auth.h"
#include "spd_conf.h"
#include "ecc/ecc.h"
#include "ecc/ecdh.h"

uint16_t ike_statem_trans_authreq(ike_statem_session_t *session);
int8_t ike_statem_state_authrespwait(ike_statem_session_t *session);

// INITIATE_START --- (INITREQ) ---> INITRESPWAIT
/*
void ike_statem_state_initiate_start(ipsec_addr_t *trigger_pkt, spd_entry_t *commanding_entry) // Argh! Set stuff up! host, triggering
{  
  // Set up the session
  ike_statem_session_t *session = mmalloc(sizeof(ike_statem_session_t)); // Double pointer memory mgmt
  list_push(session);
  
  memcpy(&session->remote, uip_addr6_remote, sizeof(uip_addr6_t));
  session->current_req_msg_id = session->current_resp_msg_id = 0;
  
  // Initialize the socket
  set_connection_address(&session->remote);
  session->client_con = udp_new(&session->remote, UIP_HTONS(500), NULL);
  
  // Prepare the arguments for later session initiation
  ike_statem_session_init_triggerdata_t *session_trigger = malloc(sizeof(ike_statem_session_init_triggerdata_t));
  memcpy(&session_trigger->trigger_pkt, trigger_pkt, sizeof(ipsec_addr_t));
  session_trigger->commanding_entry = commanding_entry;
  
  // Transition to state initrespwait
  session->next_state_fn = &ike_statem_state_initrespwait;
  session->transition_fn = &ike_statem_trans_initreq;
  session->transition_arg = &session_trigger;

  IKE_STATEM_TRANSITION(session);
}
*/



// Transmit the IKE_SA_INIT message: HDR, SAi1, KEi, Ni
// If cookie_payload in ephemeral_info is non-NULL the first payload in the message will be a COOKIE Notification.
uint16_t ike_statem_trans_initreq(ike_statem_session_t *session)
{
  payload_arg_t payload_arg = {
    .start = msg_buf,
    .session = session
  };
  
  
  SET_IKE_HDR_AS_INITIATOR(&payload_arg, IKE_PAYLOADFIELD_IKEHDR_EXCHTYPE_SA_INIT);
  
  // Should we include a COOKIE Notification? (see section 2.6)
  /**
    * Disabled as for now -Ville
  IKE_STATEM_ASSERT_COOKIE(&payload_arg);
    **/
  
  // Write the SA payload
  // From p. 79: 
  //    "SPI Size (1 octet) - For an initial IKE SA negotiation, this field MUST be zero; 
  //    the SPI is obtained from the outer header."
  //
  // (Note: We're casting to spd_proposal_tuple * in order to get rid of the const type qualifier of CURRENT_IKE_PROPOSAL)
  ike_statem_write_sa_payload(&payload_arg, (spd_proposal_tuple_t *) CURRENT_IKE_PROPOSAL, 0); 
  
  // Start KE payload
  ike_payload_generic_hdr_t *ke_genpayloadhdr = (ike_payload_generic_hdr_t *) payload_arg.start;
  SET_GENPAYLOADHDR(ke_genpayloadhdr, &payload_arg, IKE_PAYLOAD_KE);
  
  ike_payload_ke_t *ke = (ike_payload_ke_t *) payload_arg.start;
  ke->dh_group_num = uip_htons(SA_IKE_MODP_GROUP);
  ke->clear = IKE_MSG_ZERO;

  // Write key exchange data (varlen)
  // (Note: We cast the first arg of ecdh_enc...() in the firm belief that payload_arg.start is at a 4 byte alignment)
  payload_arg.start = ecdh_encode_public_key((uint32_t *) (payload_arg.start + sizeof(ike_payload_ke_t)), session->ephemeral_info->my_prv_key);
  ke_genpayloadhdr->len = uip_htons(payload_arg.start - (uint8_t *) ke_genpayloadhdr);
  // End KE payload
  
  // Start nonce payload
  ike_payload_generic_hdr_t *ninr_genpayloadhdr;
  SET_GENPAYLOADHDR(ninr_genpayloadhdr, &payload_arg, IKE_PAYLOAD_NiNr);

  // Write nonce
  random_ike(payload_arg.start, IKE_PAYLOAD_MYNONCE_LEN, session->ephemeral_info->my_nonce_seed);
  payload_arg.start += IKE_PAYLOAD_MYNONCE_LEN;
  ninr_genpayloadhdr->len = uip_htons(payload_arg.start - (uint8_t *) ninr_genpayloadhdr);
  // End nonce payload
  
  // Wrap up the IKE header and exit state
  ((ike_payload_ike_hdr_t *) msg_buf)->len = uip_htonl(payload_arg.start - msg_buf);
  SET_NO_NEXT_PAYLOAD(&payload_arg);

  return payload_arg.start - msg_buf;
}


/**
  * 
  * INITRESPWAIT --- (AUTHREQ) ---> AUTHRESPWAIT
  *              --- (INITREQ) ---> AUTHRESPWAIT
  */
int8_t ike_statem_state_initrespwait(ike_statem_session_t *session)
{
  // If everything went well, we should see something like
  // <--  HDR, SAr1, KEr, Nr, [CERTREQ]

  // Otherwise we expect a reply like 
  // COOKIE or INVALID_KE_PAYLOAD  
  session->cookie_payload = NULL; // Reset the cookie data (if it has been used)
  
  ike_payload_ike_hdr_t *ike_hdr = (ike_payload_ike_hdr_t *) msg_buf;

  // Store the peer's SPI (in network byte order)
  session->peer_spi_high = ike_hdr->sa_responder_spi_high;
  session->peer_spi_low = ike_hdr->sa_responder_spi_low;
  
  // Store a copy of this first message from the peer for later use
  // in the autentication calculations.
  COPY_FIRST_MSG(session, ike_hdr);
  
  // We process the payloads one by one
  uint8_t *peer_pub_key;
  uint16_t ke_dh_group = 0;  // 0 is NONE according to IANA's IKE registry
  u8_t *ptr = msg_buf + sizeof(ike_payload_ike_hdr_t);
  ike_payload_type_t payload_type = ike_hdr->next_payload;
  while (ptr - msg_buf < uip_datalen()) { // Payload loop
    const ike_payload_generic_hdr_t *genpayloadhdr = (const ike_payload_generic_hdr_t *) ptr;
    const uint8_t *payload_start = (uint8_t *) genpayloadhdr + sizeof(ike_payload_generic_hdr_t);
    const uint8_t *payload_end = (uint8_t *) genpayloadhdr + uip_ntohs(genpayloadhdr->len);
    spd_proposal_tuple_t *proposal_tuple;
    ike_payload_ke_t *ke_payload;
    ike_payload_notify_t *n_payload;
    
    PRINTF("Next payload is %d\n", payload_type);
    switch (payload_type) {
      /*
      FIX: Cookies disabled as for now
      case IKE_PAYLOAD_N:
      ike_payload_notify_t *n_payload = (ike_payload_notify_t *) payload_start;
      // Now what starts with the letter C?
      if (n_payload->notify_msg_type == IKE_PAYLOAD_NOTIFY_COOKIE) {
        // C is for cookie, that's good enough for me
      */
        /**
          * Although the RFC doesn't explicitly state that the COOKIE -notification
          * is a solitary payload, I believe the discussion at p. 31 implies this.
          *
          * Re-transmit the IKE_SA_INIT message with the COOKIE notification as the first payload.
          */
      /*
        session->cookie_payload_ptr = genpayloadhdr; // genpayloadhdr points to the cookie data
        IKE_STATEM_TRANSITION(session);
      }
      */
      break;
      
      case IKE_PAYLOAD_SA:
      // We expect this SA offer to a subset of ours

      // Loop over the responder's offer and that of ours in order to verify that the former
      // is indeed a subset of ours.
      session->proposal_reply = malloc(10 * sizeof(spd_proposal_tuple_t));  // 10 entries should be enough
      if (ike_statem_parse_sa_payload(CURRENT_IKE_PROPOSAL, 
                                      genpayloadhdr, 
                                      ke_dh_group,
                                      &session->sa,
                                      NULL,
                                      session->proposal_reply)) {
        PRINTF(IPSEC_IKE "The peer's offer was unacceptable\n");
        return 0;
      }
      
      PRINTF(IPSEC_IKE "Peer proposal accepted\n");
      break;
      
      //ike_statem_session_init_triggerdata_t *triggerdata = session->transition_arg;
      proposal_tuple = session->ephemeral_info->spd_entry->offer;
      ptr = (uint8_t *) payload_start;
      while (ptr < payload_end) { // Loop over proposals
        ike_payload_proposal_t *thisproposal = (ike_payload_proposal_t *) ptr;
        uint8_t *thisproposal_end = ptr + uip_ntohs(thisproposal->proposal_len);

/*
        typedef struct {
          uint8_t last_more;
          uint8_t clear;
          uint16_t proposal_len;

          uint8_t proposal_number;
          uint8_t proto_id;
          uint8_t spi_size;
          uint8_t numtransforms;
*/

        // Assert properties
        if (thisproposal->proto_id != SA_PROTO_IKE || thisproposal->spi_size != 0) {
          PRINTF(IPSEC_IKE "This doesn't look like a proposal for an IKE SA.\n");
        }

        /*
        typedef struct {
          uint8_t last_more;
          uint8_t clear;
          uint16_t transform_len;

          uint8_t type;
          uint8_t clear;
          uint16_t id;
        } ike_payload_transform_t;
        */

        // Loop over the transforms
        u8_t esn_required = 1;
        uint8_t accepted_transforms = 0;
        SA_UNASSIGN_SA(&session->sa); // Prepare the responder's SA entry for this proposal

        ptr += sizeof(ike_payload_proposal_t);
        while (ptr < thisproposal_end) {  // Transform loop
          ike_payload_transform_t *thistransform = (ike_payload_transform_t *) ptr;
          uint8_t *thistransform_end = ptr + uip_ntohs(thistransform->len);
          ptr += sizeof(ike_payload_transform_t); // ptr should now be at the beginning of whatever comes after this transform
          
          // Edge case: The KE payload _might_ have been processed, and in that case we've already
          // accepted that payload's DH group.
          if (ke_dh_group && thistransform->type == SA_CTRL_TRANSFORM_TYPE_DH && uip_ntohs(thistransform->id) != ke_dh_group) {
            // This means the the responder has already specified the DH group by
            // using the dh num field in the KE payload. Ignore all other DH groups in the SA payload.
            continue;
          }
          
          
          // We only accept sequence numbers of four bytes
          if (thistransform->type == SA_CTRL_TRANSFORM_TYPE_ESN && uip_ntohs(thistransform->id) == SA_ESN_NO)
            esn_required = 0;
          
          // Any key length attribute (the only attribute defined in the RFC)?
          if (ptr < thistransform_end) {
            ike_payload_attribute_t *attrib = (ike_payload_attribute_t *) ptr;
            
            // Assert a few values
            if (uip_ntohs(attrib->af_attribute_type) != IKE_PAYLOADFIELD_ATTRIB_VAL) {
              PRINTF(IKE "Error: Unrecognized attribute type: %x\n", uip_ntohs(attrib->af_attribute_type));
            }

            session->sa.encr_keylen = uip_ntohs(attrib->attribute_value) >> 3; // Divide by 8 to turn bits into bytes
            
            ptr += sizeof(ike_payload_attribute_t);
            if (ptr < thistransform_end) {
              PRINTF(IPSEC_IKE "Error: This transform seems to contain more than one attribute.\n");
              return 0;
            }
          } // End attribute loop

          // Loop over the proposal that we sent and see if this transform is a member of that          
          while (proposal_tuple->type != SA_CTRL_END_OF_OFFER) { // Loop over own offer
            if (proposal_tuple->type == thistransform->type) {
              
              // ( Couldn't we figure out a way to mash these two comparisons into one? )
              if (proposal_tuple->value != uip_ntohs(thistransform->id)) {
                // This is a member of our offer. Set the SA for this transform type, if not already set.
                
                if (SA_GET_PARAM_BY_INDEX(&session->sa, thistransform->type) == SA_UNASSIGNED_TYPE) {
                  SA_GET_PARAM_BY_INDEX(&session->sa, thistransform->type) = uip_ntohs(thistransform->id);
                  ++accepted_transforms;
                  PRINTF("Accepted ");
                }
              }
            }
            ++proposal_tuple;
          } // End loop over own offer
          
          // ptr should now be at the beginning of whatever comes after the transform

          // So, did we manage to find a common configuration subset?
          // If so, we're done.
          if (!esn_required && accepted_transforms == 4)
            goto proposal_accepted;
        } // End transform loop
        
      } // End proposal loop
      
      PRINTF(IKE "Error: If we end up here we couldn't accept the responder's offer. Kill the session.\n");
      
      proposal_accepted:
      break;
      
      case IKE_PAYLOAD_NiNr:
      // This is the responder's nonce
      session->ephemeral_info->peernonce_len = payload_end - payload_start;
      memcpy(&session->ephemeral_info->peernonce, payload_start, session->ephemeral_info->peernonce_len);
      PRINTF(IPSEC_IKE "Parsed %u B long nonce from the peer\n", session->ephemeral_info->peernonce_len);
      break;
      
      case IKE_PAYLOAD_KE:
      // This is the responder's public key
      ke_payload = (ike_payload_ke_t *) payload_start;

      /**
        * Our approach to selecting the DH group in the SA proposal is a bit sketchy: We grab the first one that
        * fits with our offer. This will probably work in most cases, but not all:
        
           "The Diffie-Hellman Group Num identifies the Diffie-Hellman group in
           which the Key Exchange Data was computed (see Section 3.3.2).  This
           Diffie-Hellman Group Num MUST match a Diffie-Hellman group specified
           in a proposal in the SA payload that is sent in the same message, and
           SHOULD match the Diffie-Hellman group in the first group in the first
           proposal, if such exists."
                                                                        (p. 87)
                                                                        
          It might be so that the SA payload is positioned after the KE payload, and in that case we will adopt
          the group referred to in the KE payload as the responder's choice for the SA.
          
          (Yes, payloads might be positioned in any order, consider the following from page 30:
          
           "Although new payload types may be added in the future and may appear
           interleaved with the fields defined in this specification,
           implementations SHOULD send the payloads defined in this
           specification in the order shown in the figures in Sections 1 and 2;
           implementations MUST NOT reject as invalid a message with those
           payloads in any other order."
          
          )
        *
        */

      if (session->sa.dh == SA_UNASSIGNED_TYPE) {
        // DH group not assigned because we've not yet processed the SA payload
        // Store a not of this for later SA processing.
        ke_dh_group = uip_ntohs(ke_payload->dh_group_num);
        PRINTF(IPSEC_IKE "KE payload: Using group no. %u\n", ke_dh_group);
      }
      else {
        // DH group has been assigned since we've already processed the SA
        if (session->sa.dh != uip_ntohs(ke_payload->dh_group_num)) {
          PRINTF(IPSEC_IKE "Error: DH group of the accepted proposal doesn't match that of the KE's.\n");
          return 0;
        }
        PRINTF(IPSEC_IKE "KE payload: Using group no. %u\n", session->sa.dh);
      }
      
      // Store the address to the beginning of the peer's public key
      peer_pub_key = ((uint8_t *) ke_payload) + sizeof(ike_payload_ke_t);
      break;
      
      case IKE_PAYLOAD_N:
      n_payload = (ike_payload_notify_t *) payload_start;
      if (uip_ntohs(n_payload->notify_msg_type) == IKE_PAYLOAD_NOTIFY_NO_PROPOSAL_CHOSEN) {
        PRINTF(IPSEC_IKE "Peer did not accept proposal.\n");
        return 0;
      }
      else
        PRINTF(IPSEC_IKE "Ignoring unknown Notify payload of type %u\n", uip_ntohs(n_payload->notify_msg_type));
      break;
      
      case IKE_PAYLOAD_CERTREQ:
      PRINTF(IPSEC_IKE "Ignoring certificate request payload\n");
      break;

      default:
      /**
        * Unknown / unexpected payload. Is the critical flag set?
        *
        * From p. 30:
        *
        * "If the critical flag is set
        * and the payload type is unrecognized, the message MUST be rejected
        * and the response to the IKE request containing that payload MUST
        * include a Notify payload UNSUPPORTED_CRITICAL_PAYLOAD, indicating an
        * unsupported critical payload was included.""
        */

      if (genpayloadhdr->clear > 0) {
        PRINTF(IPSEC_IKE "Error: Encountered an unknown critical payload\n");
        return 0;
      }
      else
        PRINTF(IPSEC_IKE "Ignoring unknown non-critical payload of type %u\n", payload_type);
      // Info: Ignored unknown payload

    } // End payload switch

    ptr = (uint8_t *) payload_end;
    payload_type = genpayloadhdr->next_payload;
  } // End payload loop
  
  if (payload_type != IKE_PAYLOAD_NO_NEXT) {  
    PRINTF(IPSEC_IKE "Error: Unexpected end of peer message.\n");
    return 0;
  }

  /**
    * Generate keying material for the IKE SA.
    * See section 2.14 "Generating Keying Material for the IKE SA"
    */
  PRINTF(IPSEC_IKE "Calculating shared Diffie Hellman secret\n");
  ike_statem_get_keymat(session, peer_pub_key);

  // Jump
  // Transition to state autrespwait
  session->transition_fn = &ike_statem_trans_authreq;
  session->next_state_fn = &ike_statem_state_authrespwait;

  //session->transition_arg = &session_trigger;

  IKE_STATEM_INCRMYMSGID(session);
  IKE_STATEM_TRANSITION(session);
    
  return 1;

  // This ends the INIT exchange. Borth parties has now negotiated the IKE SA's parameters and created a common DH secret.
  // We will now proceed with the AUTH exchange.
}


// Transmit the IKE_AUTH message:
//    HDR, SK {IDi, [CERT,] [CERTREQ,]
//      [IDr,] AUTH, SAi2, TSi, TSr}
uint16_t ike_statem_trans_authreq(ike_statem_session_t *session) {
  payload_arg_t payload_arg = {
    .start = msg_buf,
    .session = session
  };
  
  // Write the IKE header
  SET_IKE_HDR_AS_INITIATOR(&payload_arg, IKE_PAYLOADFIELD_IKEHDR_EXCHTYPE_IKE_AUTH);

  // Write a template of the SK payload for later encryption
  ike_payload_generic_hdr_t *sk_genpayloadhdr = (ike_payload_generic_hdr_t *) payload_arg.start;
  ike_statem_prepare_sk(&payload_arg);

  // ID payload. We use the e-mail address type of ID
  ike_payload_generic_hdr_t *id_genpayloadhdr = (ike_payload_generic_hdr_t *) payload_arg.start;
  ike_statem_set_id_payload(&payload_arg, IKE_PAYLOAD_IDi);
  ike_id_payload_t *id_payload = (ike_id_payload_t *) ((uint8_t *) id_genpayloadhdr) + sizeof(ike_payload_generic_hdr_t);
  printf("ike_id: %u\n", sizeof(ike_id));
  printf("id_genpayload_hdr: %p\n", id_genpayloadhdr);
  printf("id_genpayload_hdr->len: %u\n", uip_ntohs(id_genpayloadhdr->len));
  printf("payload_arg.start: %p\n", payload_arg.start);
  
  /**
    * Write the AUTH payload (section 2.15)
    *
    * Details depends on the type of AUTH Method specified.
    */
  ike_payload_generic_hdr_t *auth_genpayloadhdr;
  SET_GENPAYLOADHDR(auth_genpayloadhdr, &payload_arg, IKE_PAYLOAD_AUTH);
  ike_payload_auth_t *auth_payload = (ike_payload_auth_t *) payload_arg.start;
  auth_payload->auth_type = IKE_AUTH_SHARED_KEY_MIC;
  payload_arg.start += sizeof(ike_payload_auth_t);
  
  uint8_t *data_to_sign = payload_arg.start + SA_PRF_MAX_OUTPUT_LEN;
  uint16_t data_to_sign_len = ike_statem_get_authdata(session, 1, data_to_sign, id_payload, uip_ntohs(id_genpayloadhdr->len) - sizeof(ike_payload_generic_hdr_t));
  
  // Calculate the PSK hash
  prf_data_t data = {
    .out = payload_arg.start,
    .key = (uint8_t *) ike_auth_sharedsecret,
    .keylen = sizeof(ike_auth_sharedsecret),
    .data = data_to_sign,
    .datalen = data_to_sign_len
  };
  prf_psk(session->sa.prf, &data);
  payload_arg.start += SA_PRF_OUTPUT_LEN(session);
  auth_genpayloadhdr->len = uip_htons(payload_arg.start - (uint8_t *) auth_genpayloadhdr); // Length of the AUTH payload

  end:
  /**
    * Write SAi2 (offer for the child SA)
    */
  session->ephemeral_info->local_spi = SAD_GET_NEXT_SAD_LOCAL_SPI;
  ike_statem_write_sa_payload(&payload_arg, session->ephemeral_info->spd_entry->offer, session->ephemeral_info->local_spi);

  /**
    * The TS payload is decided by the triggering packet's header and the policy that applies to it
    *
    * Read more at "2.9.  Traffic Selector Negotiation" p. 40
    */
  //ike_statem_write_tsitsr(&payload_arg);

    
  // Protect the SK payload. Write trailing fields.
  ike_statem_finalize_sk(&payload_arg, sk_genpayloadhdr, payload_arg.start - (((uint8_t *) sk_genpayloadhdr) + sizeof(ike_payload_generic_hdr_t)));

  return uip_ntohl(((ike_payload_ike_hdr_t *) msg_buf)->len);  // Return written length
}


/**
  * AUTH response wait state
  */
int8_t ike_statem_state_authrespwait(ike_statem_session_t *session)
{
  // If everything went well, we should see something like
  // <--  HDR, SK {IDr, [CERT,] AUTH, SAr2, TSi, TSr}
  PRINTF("state_authrespwait stub!\n");
  return 1;
}

//   ike_payload_ike_hdr_t *ike_hdr = msg_buf;
//   
//   ike_ts_payload_t *tsi, *tsr;
//   uint8_t *ptr = ike_hdr + sizeof(ike_payload_ike_hdr_t);
//   ike_payload_type_t payload_type = ike_hdr->next_payload;
//   while (ptr - msg_buf < msg_buf_len) { // Payload loop
//     ike_payload_generic_hdr_t *genpayloadhdr = ptr;
//     uint8_t *payload_start = genpayloadhdr + sizeof(genpayloadhdr);
//     uint8_t *payload_end = genpayloadhdr + uip_ntohs(genpayloadhdr->len);
//     
//     switch (payload_type) {
//       case IKE_PAYLOAD_SK:
//       if (ike_statem_decrypt(session, ptr)) {
//         ike_statem_remove_session(session);
//         return;
//       }
//       break;
//       
//       case IKE_PAYLOAD_IDr:
//       break;
//       
//       case IKE_PAYLOAD_AUTH:
//       break;
// 
//       case IKE_PAYLOAD_SA:
//       break;
//       
//       case IKE_PAYLOAD_TSi:
//       tsi = payload_start + sizeof(ike_payload_generic_hdr_t);
//       break;
//       
//       case IKE_PAYLOAD_TSr:
//       tsr = payload_start + sizeof(ike_payload_generic_hdr_t);
//       break;
//       
//       default:
//       // Info: Unexpected payload
//     }
//     
//     ptr = payload_end;
//     payload_type = genpayloadhdr->next_payload;
//   }
//   
  /**
    * Assert values of traffic selectors
    */
  // uint8_t tmp[100];
  // ike_statem_write_tsitsr(session, &tmp);
  // 
  // // Assert Traffic Selectors' syntax
  // ipsec_assert_ts_invariants  
  // 
  // 
  // ike_statem_assert_tsa_is_subset_of_tsb(ai, ar, tmp + ioffset, tmp + roffset);  
  // ts_to_addr_set(ai, ar);
  // 
  /**
    * Derive SA key material (KEYMAT calulcation)
    */
  
  /* 
  ike_ts_t *tsi[IKE_PAYLOADFIELD_MAX_TS_COUNT], *tsr[IKE_PAYLOADFIELD_MAX_TS_COUNT];
  ike_statem_write_tsitsr()
  
  // Check that they fit
  //
  
  ike_ts_t *tsi[IKE_PAYLOADFIELD_MAX_TS_COUNT], *tsr[IKE_PAYLOADFIELD_MAX_TS_COUNT];
  tsi[0] = tsi[1] = tsr[0] = tsr[1] = NULL;
  ike_ts_t **tsarr = NULL;

  ipsec_addr_set_t addrset;
  
  // We process the payloads one by one
  long ke_dh_group = -1;
  ptr += msg_buf + sizeof(ike_payload_ike_hdr_t);
  while (ptr - msg_buf < msg_buf_len) { // Payload loop
    ike_payload_generic_hdr_t *genpayloadhdr = ptr;
    uint8_t *payload_start = genpayloadhdr + sizeof(genpayloadhdr);
    uint8_t *payload_end = genpayloadhdr + uip_ntohs(genpayloadhdr->len);
    
    switch (genpayloadhdr->next_type) {

      case IKE_PAYLOAD_AUTH:
      // Verify that the peer's AUTH payload matches its identity
      

      case IKE_PAYLOAD_TSr:
      tsarr = &tsi;
      
      case IKE_PAYLOAD_TSi:
      if (tsarr == NULL)
        tsarr = &tsr;
      
      ike_ts_payload_t *ts_payload = payload_start;

      int i;
      ptr += sizeof(ts_payload);
      for (i = 0; i < ts_payload->number_of_ts; ++i) {
        *tsarr[i] = ptr;
        ptr += sizeof(ike_ts_t);
      }
      
      tsarr = NULL;      
      break;
  }

  
  // Investigate if the TS offer is acceptable
  //
  // The SA that we're trying to set up will transport traffic from the responder (the other party)
  // to us (the initiator). Therefore the responder is the source of the traffic and the initiator is
  // its destination.
  spd_entry_t *spd_entry;
  
  // The goal is to negotiate the largest set of traffic that our policy allows
  //
  // We need to verify that the returned traffic selectors form a subset of those we sent
  
  
  // First attempt: Try to match the wide second traffic selectors
  uint8_t i = IKE_PAYLOADFIELD_MAX_TS_COUNT;
  do {
    if (tsi[i] != NULL && ipsec_assert_ts_invariants(tsi[i]) &&
      tsr[i] != NULL && ipsec_assert_ts_invariants(tsr[i]) &&    
      (spd_entry = spd_get_entry_by_ts(tsi[i], tsr[i], triggering_pkt))->proc_action == SPD_ACTION_PROTECT) {
        goto success;
    }
    --i;
  } while (i >= 0)
  // Error: TSs not acceptable. Kill the session.
  
  success:
  // ok!
  
  addr_set = tsi / tsr
  
  ipsec_addr_set_t traffic;
  traffic
  
  GET_ADDRSETFROMTS(&addrset, ts_src, ts_dst);
}
*/

// 
// Upon receiving a request:
// Create an ipsec_addr_set_t:
//  use TSr2 as the destination
//  use TSi2 as the source
// Try to match it with an SPD entry
// If no match, try the same but for TS*1
// If still no match, send an error
// 
// If match, create the SA using the instanciated SPD entry as the traffic selector
// 




















/**
  * 
  * INITRESPWAIT --- (AUTHREQ) ---> AUTHRESPWAIT
  *              --- (INITREQ) ---> AUTHRESPWAIT
  */
// void ike_statem_state_initrespwait(ike_statem_session_t *session)
// 
// 
// void ike_statem_state_auth_wait(ike_statem_session_t *session)
// {
//   
// }
// 
// 
/**
  * States (nodes) for the session responder machine
  */
//   
// void ike_statem_state_respond_start(ike_statem_session_t *session) // Always given a NULL pointer
// {
//   ike_payload_ikehdr *ikehdr = &msg_buf;
// 
//   // ike_payload_nxt_hdr
// 
//   if (NTOHL(ikehdr.remoteSPI) == 0) {
//     // Init request. Make transition.
//     session = ike_statem_create_new_session( );
//     memcpy(session.remote, uip_addr6_remote, sizeof(uip_addr6_t));
//     session.re
//     session.past = IKE_STATEM_STATE_STARTNETTRAFIC;
//     session.current = IKE_STATEM_STATE_AUTHWAIT;
//   }
// }
// 

/**
  * Transitions (edges)
  */