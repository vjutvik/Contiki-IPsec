#include "machine.h"
#include "ecc/ecc.h"
#include "ecc/ecdh.h"

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

  IKE_STATEM_EXITSTATE(session);
}
*/



// Transmit the IKE_SA_INIT message: HDR, SAi1, KEi, Ni
// If cookie_data in ephemeral_info is non-NULL the first payload in the message will be a COOKIE Notification.
void ike_statem_trans_initreq(ike_statem_session_t *session)
{
  payload_arg_t payload_arg = {
    .start = udp_buf,
    .session = session
  };
  
  // Write the IKE header
  ike_payload_ike_hdr_t *ike_hdr = payload_arg.start;
  
  SET_IKE_HDR_AS_INITIATOR(&payload_arg, IKE_PAYLOADFIELD_IKEHDR_EXCHTYPE_SA_INIT);
  //payload_arg.start += sizeof(ike_payload_ike_hdr_t);
  
  // Should we include a COOKIE Notification? (see section 2.6)
  IKE_STATEM_ASSERT_COOKIE(&payload_arg);
  
  // Write the SA payload
  // From p. 79: 
  //    "SPI Size (1 octet) - For an initial IKE SA negotiation, this field MUST be zero; 
  //    the SPI is obtained from the outer header."
  ike_statem_write_sa_payload(&payload_arg, spdconf_ike_proposal, 0);
  
  // Start KE payload
  ike_payload_generic_hdr_t *ke_genpayloadhdr = payload_arg->start;
  SET_GENPAYLOADHDR(ke_genpayloadhdr, payload_arg, IKE_PAYLOAD_KE);
  
  ike_payload_ke_t *ke = payload_arg->start;
  ke->dh_group_num = UIP_HTONS(SA_IKE_MODP_GROUP);
  ke->clear = IKE_MSG_ZERO;

  // Write key exchange data (varlen)
  ptr = ecdh_encode_public_key(ptr + sizeof(ike_payload_ke_t), session->ephemeral_info->my_prv_key);
  ke_genpayloadhdr->len = UIP_HTONS((ptr - ((uint8_t *) ke_genpayloadhdr));
  // End KE payload
  
  // Start nonce payload
  ike_payload_generic_hdr_t *ninr_genpayloadhdr;
  payload_ptr->start = ptr;
  SET_GENPAYLOADHDR(ninr_genpayloadhdr, payload_arg, IKE_PAYLOAD_NiNr);

  // Write nonce
  random_ike(payload_arg->start, IKE_PAYLOAD_MYNONCE_LEN, &session->ephemeral_info.my_nonce_seed);
  ninr_genpayloadhdr->len = UIP_HTONS(payload_arg->start - (uint8_t *) ninr_genpayloadhdr);
  // End nonce payload
    
  // Wrap up the IKE header and exit state
  ike_hdr->len = UIP_HTONL(payload_arg->start - udp_buf);
  SET_NO_NEXT_PAYLOAD(payload_arg);
}


/**
  * 
  * INITRESPWAIT --- (AUTHREQ) ---> AUTHRESPWAIT
  *              --- (INITREQ) ---> AUTHRESPWAIT
  */
void ike_statem_state_initrespwait(ike_statem_session_t *session)
{
  // If everything went well, we should see something like
  // <--  HDR, SAr1, KEr, Nr, [CERTREQ]

  // Otherwise we expect a reply like 
  // COOKIE or INVALID_KE_PAYLOAD
  
  session->ephemeral_info->cookie_data = NULL; // Reset the cookie data (if it has been used)
  
  ike_payload_ike_hdr_t *ike_hdr = udp_buf;
  
  // Store a copy of this first message from the peer for later use
  // in the autentication calculations.
  COPY_FIRST_MSG(session, ike_hdr);
  
  // We process the payloads one by one
  uint8_t *peer_pub_key;
  uint16_t ke_dh_group = 0;  // 0 is NONE according to IANA
  ptr += udp_buf + sizeof(ike_payload_ike_hdr_t);
  ike_payload_type_t payload_type = ike_hdr->next_payload;
  while (ptr - udp_buf < udp_buf_len) { // Payload loop
    const ike_payload_generic_hdr_t *genpayloadhdr = ptr;
    const uint8_t *payload_start = genpayloadhdr + sizeof(genpayloadhdr);
    const uint8_t *payload_end = genpayloadhdr + UIP_NTOHS(genpayloadhdr->len);
    
    switch (payload_type) {
      case IKE_PAYLOAD_N:
      ike_payload_notify_t *n_payload = payload_start;
      // Now what starts with the letter C?
      if (n_payload->notify_msg_type == IKE_PAYLOAD_NOTIFY_COOKIE) {
        // C is for cookie, that's good enough for me

        /**
          * Although the RFC doesn't explicitly state that the COOKIE -notification
          * is a solitary payload, I believe the discussion at p. 31 implies this.
          *
          * Re-transmit the IKE_SA_INIT message with the COOKIE notification as the first payload.
          */
        session->ephemeral_info->cookie_data_ptr = genpayloadhdr; // genpayloadhdr points to the cookie data
        IKE_STATEM_EXITSTATE(session);
      }
      break;
      
      case IKE_PAYLOAD_SA:
      // We expect this SA offer to a subset of ours

      // Loop over the responder's offer and that of ours in order to verify that the former
      // is indeed a subset of ours.
      //ike_statem_session_init_triggerdata_t *triggerdata = session->transition_arg;
      spd_proposal_tuple_t *proposal_tuple = session->ephemeral_info->triggering_pkt->spd_entry->offer;
      while (ptr < payload_end) { // Start proposals
        ike_payload_proposal_t *thisproposal = ptr;
        uint8_t *thisproposal_end = ptr + UIP_NTOHS(thisproposal->proposal_len);
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
          IKEPRINTF("This doesn't look like a proposal for an IKE SA.\n");
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
        bool esn_required = true;
        uint8_t accepted_transforms = 0;
        SA_UNASSIGN_SA(&session->sa); // Prepare the responder's SA entry for this proposal

        while (ptr < thisproposal_end) {  // Transform loop
          ike_payload_transform_t *thistransform = ptr;
          uint8_t *thistranform_end = ptr + UIP_NTOHS(thistransform->len);
          ptr += sizeof(ike_payload_transform_t); // ptr should now be at the beginning of whatever comes after this transform
          
          // Edge case: The KE payload _might_ have been processed, and in that case we've already
          // accepted that payload's DH group.
          if (ke_dh_group && thistransform->type == SA_CTRL_TRANSFORM_TYPE_DH && UIP_NTOHS(thistransform->id) != ke_dh_group) {
            // This means the the responder has already specified the DH group by
            // using the dh num field in the KE payload. Ignore all other DH groups in the SA payload.
            continue;
          }
          
          
          // We only accept sequence numbers of four bytes
          if (thistransform->type == SA_CTRL_TRANSFORM_TYPE_ESN && UIP_NTOHS(thistransform->id) == SA_ESN_NO)
            esn_required = false;
          
          // Any key length attribute (the only attribute defined in the RFC)?
          if (ptr < thistransform_end) {
            ike_payload_attribute_t *attrib = ptr;
            
            // Assert a few values
            if (attrib->af_attribute_type != IKE_PAYLOADFIELD_ATTRIB_VAL)
              PRINTF(IKE "Error: Unrecognized attribute type\n");

            session->sa.encr_keylen = UIP_NTOHS(attrib->af_attribute_value) >> 3; // Divide by 8 to turn bits into bytes
            
            ptr += sizeof(ike_payload_attribute_t);
            if (ptr < thistransform_end) {
              PRINTF(IKE "Error: This transform seems to contain more than one attribute. Kill the session.\n");
              ike_statem_remove_session(session);
              return;
            }
          }

          // Loop over the proposal that we sent and see if this transform is a member of that          
          while (proposal_tuple->type != SA_CTRL_END_OF_OFFER) { // Loop over own offer
            if (proposal_tuple->type == thistransform->type) {
              
              // ( Couldn't we figure out a way to mash these two comparisons into one? )
              if (proposal_tuple->value != UIP_NTOHS(thistransform->id)) {
                // This is a member of our offer. Set the SA for this transform type, if not already set.
                
                if (SA_GET_PARAM_BY_INDEX(&session->sa, thistransform->type) == SA_UNASSIGNED_TYPE) {
                  SA_GET_PARAM_BY_INDEX(&session->sa, thistransform->type) = UIP_NTOHS(thistransform->id);
                  ++accepted_transforms;
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
      session->ephemeral_info->noncelen = payload_end - payload_start;
      memcpy(&session->ephemeral_info->peer_nonce, payload_start, session->ephemeral_info->noncelen);
      break;
      
      case IKE_PAYLOAD_KE:
      // This is the responder's public key
      ike_payload_ke_t *ke_payload = payload_start;

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
          
         */
      if (session->sa.dh == SA_UNASSIGNED_TYPE) {
        // DH group not assigned because we've not yet processed the SA payload
        // Store a not of this for later SA processing.
        ke_dh_group = UIP_NTOHS(ke_payload->dh_group_num);      
      }
      else {
        // DH group has been assigned since we've already processed the SA
        if (session->sa.dh != UIP_NTOHS(ke_payload->dh_group_num)) {
          ike_statem_remove_session(session);
          return;
          PRINTF(IKE "Error: DH group of the accepted proposal doesn't match that of the KE's. Kill the session.\n");
        }
      }
      
      // Store the address to the beginning of the peer's public key
      peer_pub_key = ((uint8_t *) ke_payload) + sizeof(ke_payload);
      break;
      
      case IKE_PAYLOAD_CERTREQ:
      // Info: Ignored certificate req. payload
      break;
      
      case IKE_PAYLOAD_NO_NEXT:
      goto done;

      // 
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
        PRINTF(IKE "Error: Encountered an unknown critical payload\n");
        ike_statem_remove_session(session); // Kill the session
        return;
      }
      // Info: Ignored unknown payload

    } // End payload switch

    ptr = payload_end;
    payload_type = genpayloadhdr->next_payload;
  } // End payload loop
  PRINTF(IKE "Error: Unexpected end of data. Send a new request.\n");

  done: // Done parsing
  /**
    * Generate keying material for the IKE SA.
    * See section 2.14 "Generating Keying Material for the IKE SA"
    */
  ike_statem_get_keymat(session, peer_pub_key);

  // Jump
  // Transition to state autrespwait
  session->next_state_fn = &ike_statem_state_authrespwait;
  session->transition_fn = &ike_statem_trans_authreq;
  //session->transition_arg = &session_trigger;

  IKE_STATEM_INCRMYMSGID(session);
  IKE_STATEM_EXITSTATE(session);
  
  // This ends the INIT exchange. Borth parties has now negotiated the IKE SA's parameters and created a common DH secret.
  // We will now proceed with the AUTH exchange.
}


// Transmit the IKE_AUTH message:
//    HDR, SK {IDi, [CERT,] [CERTREQ,]
//      [IDr,] AUTH, SAi2, TSi, TSr}

void ike_statem_trans_authreq(ike_statem_session_t *session) {
  payload_arg_t payload_arg = {
    .start = udp_buf,
    .session = session
  };
  
  // Write the IKE header
  SET_IKE_HDR_AS_INITIATOR(&payload_arg, IKE_PAYLOADFIELD_IKEHDR_EXCHTYPE_IKE_AUTH);

  // Write a template of the SK payload for later encryption
  ike_payload_generic_hdr_t *sk_genpayloadhdr = payload_arg->start;
  ike_statem_prepare_sk(&payload_arg);

  // ID payload
  ike_payload_generic_hdr_t *id_genpayloadhdr;
  SET_GENPAYLOADHDR(id_genpayloadhdr, &payload_arg, IKE_PAYLOAD_ID);

  ike_id_payload_t *id_payload;
  SET_IDPAYLOAD(id_payload, &payload_arg, some_suitable_id_type);   // FIX
  
  // FIX: Write the ID payload data  
  uint8_t id_payload_len = sizeof(id_payload) + bogus_idpayload_data_len; // FIX: This len must be the size of the ID payload + its data

  // Set the size
  id_genpayloadhdr->len = UIP_HTONS(id_payload_len);
  
  /**
    * Write the AUTH payload (section 2.15)
    *
    * The AUTH payload is hash of some sort of the string
    * InitiatorSignedOctets = RealMessage1 | NonceRData | prf(SK_pi, RestOfInitIDPayload)
    * result = prf( prf(Shared Secret, "Key Pad for IKEv2"), <InitiatorSignedOctets>)
    *
    * Details depends on the type of AUTH Method specified.
    */
  SET_GENPAYLOADHDR(auth_genpayloadhdr, &payload_arg, IKE_PAYLOAD_AUTH);
  ike_payload_auth_t *auth_payload = payload_arg->start;
  auth_payload.auth_method = IKE_AUTH_SHARED_KEY_MIC;
  payload_arg->start += sizeof(auth_payload);
  
  // Assemble the data string that is to be hashed using the UDP buffer as the temporary storage
  uint8_t *assembly_start = payload_arg->start + 40; // Offset must be at a sufficient margin for the rest of the AUTH payload  
  uint8_t *assembly_ptr = assembly_start;

  // RealMessage1
  // (We assume that RealMessage1 is our very first message to the peer (and not any subsequent message including a cookie))
  uint8_t *udp_buf_save = udp_buf;  // ike_statem_trans_initreq() writes to the address of udp_buf
  udp_buf = assembly_start;
  ike_statem_trans_initreq(session);  // Re-write our first message to assembly_start
  assembly_ptr += ((ike_hdr_t *) assembly_start)->len;
  udp_buf = udp_buf_save;
  
  // NonceRData
  memcpy(assembly_ptr, session->ephemeral_info->peer_nonce, session->ephemeral_info->peernonce_len);
  assembly_ptr += session->ephemeral_info->peernonce_len;
  
  // MACedIDForI ( prf(SK_pi, IDType | RESERVED | InitIDData) = prf(SK_pi, RestOfInitIDPayload) )
  prf_data_t prf_data =
    {
      .out = assembly_ptr,
      .outlen = 0,
      .key = session->ephemeral_info->sk_pi,
      .keylen = SA_PRF_CURRENT_KEYMATLEN(session), // sk_pi is always of the PRF's key length
      .data = id_payload,
      .datalen = id_payload_len
    };
  prf(session->sa.prf, &prf_data);
  assembly_ptr += SA_PRF_CURRENT_KEYMATLEN(session);

  // prf( prf(Shared Secret, "Key Pad for IKEv2"), <InitiatorSignedOctets>)
  prf_data =
    {
      .out = assembly_ptr,
      .key = &auth_sharedsecret,
      .keylen = sizeof(auth_sharedsecret),
      .data_ptr = &auth_keypad,
      .datalen = sizeof(auth_keypad)
    };
  prf(session->sa.prf, &prf_data);

  prf_data =
    {
      .out = payload_arg.start,  // This will write the AUTH data to the AUTH payload
      .key = assembly_ptr,
      .keylen = SA_PRF_CURRENT_KEYMATLEN(session),
      .data_ptr = assembly_start,
      .datalen = assembly_ptr - assembly_start
    };
  prf(session->sa.prf, &prf_data);
  payload_arg.start += SA_PRF_CURRENT_KEYMATLEN(session); // start is now at the end of the AUTH payload
  auth_genpayloadhdr->len = UIP_HTONS(payload_arg.start - auth_genpayloadhdr); // Length of the AUTH payload

  /**
    * Write SAi2 (offer for the child SA)
    */
  session->ephemeral_info->local_spi = SAD_GET_NEXT_SAD_LOCAL_SPI;
  ike_statem_write_sa_payload(&payload_arg, ((ike_statem_session_t *) session->transition_arg)->spd_entry->offer, session->ephemeral_info->local_spi);
  
  /**
    * The TS payload is decided by the triggering packet's header and the policy that applies to it
    *
    * Read more at "2.9.  Traffic Selector Negotiation" p. 40
    */
  ike_statem_write_tsitsr(&payload_arg);

  // All payloads have been written. Finish up.

  // Protect the SK payload. Write trailing fields.
  ike_statem_finalize_sk(payload_arg->session, sk_genpayloadhdr, payload_arg->start - id_genpayloadhdr);
}


/**
  * AUTH response wait state
  */
void ike_statem_state_authrespwait(ike_statem_session_t *session)
{
  // If everything went well, we should see something like
  // <--  HDR, SK {IDr, [CERT,] AUTH, SAr2, TSi, TSr}
  ike_payload_ike_hdr_t *ike_hdr = udp_buf;
  
  ike_ts_payload_t *tsi, *tsr;
  uint8_t *ptr = ike_hdr + sizeof(ike_payload_ike_hdr_t);
  ike_payload_type_t payload_type = ike_hdr->next_payload;
  while (ptr - udp_buf < udp_buf_len) { // Payload loop
    ike_payload_generic_hdr_t *genpayloadhdr = ptr;
    uint8_t *payload_start = genpayloadhdr + sizeof(genpayloadhdr);
    uint8_t *payload_end = genpayloadhdr + UIP_NTOHS(genpayloadhdr->len);
    
    switch (payload_type) {
      case IKE_PAYLOAD_SK:
      if (ike_statem_decrypt(session, ptr)) {
        ike_statem_remove_session(session);
        return;
      }
      break;
      
      case IKE_PAYLOAD_IDr:
      break;
      
      case IKE_PAYLOAD_AUTH:
      break;

      case IKE_PAYLOAD_SA:
      break;
      
      case IKE_PAYLOAD_TSi:
      tsi = payload_start + sizeof(ike_payload_generic_hdr_t);
      break;
      
      case IKE_PAYLOAD_TSr:
      tsr = payload_start + sizeof(ike_payload_generic_hdr_t);
      break;
      
      default:
      // Info: Unexpected payload
    }
    
    ptr = payload_end;
    payload_type = genpayloadhdr->next_payload;
  }
  
  /**
    * Assert values of traffic selectors
    */
  uint8_t tmp[100];
  ike_statem_write_tsitsr(session, &tmp);
  
  // Assert Traffic Selectors' syntax
  ipsec_assert_ts_invariants  
  
  
  ike_statem_assert_tsa_is_subset_of_tsb(ai, ar, tmp + ioffset, tmp + roffset);  
  ts_to_addr_set(ai, ar);
  
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
  ptr += udp_buf + sizeof(ike_payload_ike_hdr_t);
  while (ptr - udp_buf < udp_buf_len) { // Payload loop
    ike_payload_generic_hdr_t *genpayloadhdr = ptr;
    uint8_t *payload_start = genpayloadhdr + sizeof(genpayloadhdr);
    uint8_t *payload_end = genpayloadhdr + UIP_NTOHS(genpayloadhdr->len);
    
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
  */
}

Upon receiving a request:
Create an ipsec_addr_set_t:
	use TSr2 as the destination
	use TSi2 as the source
Try to match it with an SPD entry
If no match, try the same but for TS*1
If still no match, send an error

If match, create the SA using the instanciated SPD entry as the traffic selector





















/**
  * 
  * INITRESPWAIT --- (AUTHREQ) ---> AUTHRESPWAIT
  *              --- (INITREQ) ---> AUTHRESPWAIT
  */
void ike_statem_state_initrespwait(ike_statem_session_t *session)


void ike_statem_state_auth_wait(ike_statem_session_t *session)
{
  
}


/**
  * States (nodes) for the session responder machine
  */
  
void ike_statem_state_respond_start(ike_statem_session_t *session) // Always given a NULL pointer
{
  ike_payload_ikehdr *ikehdr = &udp_buf;

  // ike_payload_nxt_hdr

  if (NTOHL(ikehdr.remoteSPI) == 0) {
    // Init request. Make transition.
    session = ike_statem_create_new_session( );
    memcpy(session.remote, uip_addr6_remote, sizeof(uip_addr6_t));
    session.re
    session.past = IKE_STATEM_STATE_STARTNETTRAFIC;
    session.current = IKE_STATEM_STATE_AUTHWAIT;
  }
}


/**
  * Transitions (edges)
  */