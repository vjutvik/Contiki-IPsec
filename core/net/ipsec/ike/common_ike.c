/**
 * \addtogroup ipsec
 * @{
 */

/**
 * \file
 * 		Common functionality for IKEv2. Mostly helpers for the state machine.
 * \author
 *		Vilhelm Jutvik <ville@imorgon.se>
 *
 */

/*
 * Copyright (c) 2012, Vilhelm Jutvik.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * This file is part of the Contiki operating system.
 */

/**
  * Pertains to Contiki's implementation of RFC 5996 (IKEv2)
  */

#include <lib/random.h>
#include "contikiecc/ecc/ecc.h"
#include "contikiecc/ecc/ecdh.h"
#include "transforms/integ.h"
#include "transforms/encr.h"
#include "machine.h"
#include "spd_conf.h"
#include "common_ike.h"
#include "auth.h"
#include "uip.h"


/**
  * State machine for servicing an established session
  */
/*
void ike_statem_state_common_createchildsa(session, addr_t triggering_pkt, spd_entry_t commanding_entry)
{
  
}
*/

#define PRINTTSPAIR(ts_me_ptr, ts_peer_ptr)   \
  do {                                        \
    ipsec_addr_set_t addr_set;                \
    uip_ip6addr_t peer;                       \
    addr_set.peer_addr_from = &peer;          \
    addr_set.peer_addr_to = &peer;            \
    ts_pair_to_addr_set(&addr_set, ts_me_ptr, ts_peer_ptr);   \
    PRINTADDRSET(&addr_set);                   \
  } while (0)



/**
  * Functions common to all state machines
  */

/**
  * Write a notification payload (p. 97)
  *
  * \parameter payload_arg Payload argument
  * \parameter proto_id The type of protocol concerned.
  * \parameter spi Only used in conjunction with INVALID_SELECTORS and REKEY_SA, zero otherwise.
  * \parameter type Notificiation message type.
  * \parameter notify_payload Address of the payload. Null if none.
  * \parameter notify_payload_len Length of the payload starting at notify_payload.
  */
void ike_statem_write_notification(payload_arg_t *payload_arg, 
                                sa_ipsec_proto_type_t proto_id,
                                uint32_t spi, 
                                notify_msg_type_t type, 
                                uint8_t *notify_payload, 
                                uint8_t notify_payload_len)
{
  uint8_t *beginning = payload_arg->start;
  
  ike_payload_generic_hdr_t *notify_genpayloadhdr = (ike_payload_generic_hdr_t *) payload_arg->start;
  SET_GENPAYLOADHDR(notify_genpayloadhdr, payload_arg, IKE_PAYLOAD_N);
  
  ike_payload_notify_t *notifyhdr = (ike_payload_notify_t *) payload_arg->start;
  notifyhdr->proto_id = proto_id;
  notifyhdr->notify_msg_type = uip_ntohs(type);
  payload_arg->start += sizeof(ike_payload_notify_t);
  if (spi != 0) {
    notifyhdr->spi_size = 4;
    *payload_arg->start = spi;
    payload_arg->start += 4;
  }
  else
    notifyhdr->spi_size = 0;

  // Write the notify payload, if any
  if (notify_payload != NULL) {    
    memcpy(payload_arg->start, notify_payload, notify_payload_len);
    payload_arg->start += notify_payload_len;
  }
  
  notify_genpayloadhdr->len = uip_htons(payload_arg->start - beginning);
}

/**
  * Writes the initial TSi and TSr payloads in the role as the initiator
  */
void ike_statem_write_tsitsr(payload_arg_t *payload_arg, const ipsec_addr_set_t *ts_addr_set)
{
  //ipsec_addr_set_t *spd_selector = &payload_arg->session->ephemeral_info->spd_entry->selector;
  uint8_t *ptr = payload_arg->start;
  //PRINTF("packet_tag.addr is: ");
  //PRINT6ADDR(trigger_addr->addr);
  //PRINTF("\n");
  
  
  /**
    * Initiator's traffic selectors (i.e. describing the source of the traffic)
    *
    * In blatant violation of the RFC the PFP flags are hardcoded. PFP is only used on
    * the address selector, other parameters are fetched from the matching SPD entry.
    */
  //
  // PFP is hardcoded. PFP(SRCADDR) PFP(DSTADDR), other parameters are taken from SPD entry

  // TSi payload
  ike_payload_generic_hdr_t *tsi_genpayloadhdr;
  uint16_t tsir_size = sizeof(ike_payload_generic_hdr_t) + sizeof(ike_payload_ts_t) + 1 * sizeof(ike_ts_t);
  SET_GENPAYLOADHDR(tsi_genpayloadhdr, payload_arg, IKE_PAYLOAD_TSi);
  tsi_genpayloadhdr->len = uip_htons(tsir_size);
  ike_payload_ts_t *tsi_payload = (ike_payload_ts_t *) payload_arg->start;
  SET_TSPAYLOAD(tsi_payload, 1);
  payload_arg->start += sizeof(ike_payload_ts_t);
  
  // Initiator's first traffic selector (triggering packet's params)
  ike_ts_t *tsi1 = (ike_ts_t *) payload_arg->start;
  payload_arg->start += sizeof(ike_ts_t);
 
  // TSr payload
  ike_payload_generic_hdr_t *tsr_genpayloadhdr = (ike_payload_generic_hdr_t *) payload_arg->start;
  SET_GENPAYLOADHDR(tsr_genpayloadhdr, payload_arg, IKE_PAYLOAD_TSr);
  tsr_genpayloadhdr->len = uip_htons(tsir_size);
  ike_payload_ts_t *tsr_payload = (ike_payload_ts_t *) payload_arg->start;  
  SET_TSPAYLOAD(tsr_payload, 1);
  payload_arg->start += sizeof(ike_payload_ts_t);
  
  // Responder's first traffic selector
  ike_ts_t *tsr1 = (ike_ts_t *) payload_arg->start;
  payload_arg->start += sizeof(ike_ts_t);

  if (IKE_STATEM_IS_INITIATOR(payload_arg->session))
    instanciate_spd_entry(ts_addr_set, &payload_arg->session->peer, tsi1, tsr1);
  else
    instanciate_spd_entry(ts_addr_set, &payload_arg->session->peer, tsr1, tsi1);
    
  PRINTF("WRITING TRAFFIC SELECTORS:\n");
  PRINTADDRSET(ts_addr_set);
  
  // PRINTF("trigger_addr->addr;\n");
  //   PRINT6ADDR(trigger_addr->addr);
  MEMPRINTF("\ntsi_genpayloadhdr", tsi_genpayloadhdr, uip_ntohs(tsi_genpayloadhdr->len));

  
  MEMPRINTF("tsr_genpayloadhdr", tsr_genpayloadhdr, uip_ntohs(tsr_genpayloadhdr->len));
  PRINTF("len: %u\n", payload_arg->start - ptr);
}


/**
  * Sends a single Notify payload encapsulated in an SK payload if cryptographic keys have been negotiated. Only to be called from state
  * function.
  *
  * The IKE header's exchange type will be recycled from the header currently sitting in msg_buf. The type will always be response. If the exchange is any other than SA_INIT
  * the notify payload will be protected by an encrypted payload.
  *
  * \param session Session concerned
  * \param type Notify message type. 0 does nothing.
  */
void ike_statem_send_single_notify(ike_statem_session_t *session, notify_msg_type_t type)
{
  payload_arg_t payload_arg = {
    .start = msg_buf,
    .session = session
  };
  
  // Don't do anything if type is 0
  if (!type)
    return;

  PRINTF(IPSEC_IKE "Sending single notification to peer of type %u\n", type);

  ike_payload_ike_hdr_t *old_ike_hdr = (ike_payload_ike_hdr_t *) msg_buf;
  uint8_t protect = old_ike_hdr->exchange_type == IKE_PAYLOADFIELD_IKEHDR_EXCHTYPE_IKE_AUTH || old_ike_hdr->exchange_type == IKE_PAYLOADFIELD_IKEHDR_EXCHTYPE_CREATE_CHILD_SA;
  
  SET_IKE_HDR_AS_RESPONDER(&payload_arg, old_ike_hdr->exchange_type, IKE_PAYLOADFIELD_IKEHDR_FLAGS_RESPONSE);

  ike_payload_generic_hdr_t *sk_genpayloadhdr = (ike_payload_generic_hdr_t *) payload_arg.start;
  if (protect) {
    // Write a template of the SK payload for later encryption
    ike_statem_prepare_sk(&payload_arg);
  }

  /**
    * Write notification requesting the peer to create transport mode SAs
    */
  ike_statem_write_notification(&payload_arg, SA_PROTO_IKE, 0, type, NULL, 0);

  if (protect) {
    // Protect the SK payload. Write trailing fields.
    ike_statem_finalize_sk(&payload_arg, sk_genpayloadhdr, payload_arg.start - (((uint8_t *) sk_genpayloadhdr) + sizeof(ike_payload_generic_hdr_t)));
  }
  
  // Send!
  ike_statem_send(session, uip_ntohl(((ike_payload_ike_hdr_t *) msg_buf)->len));
  
  return;
}


/**
  * Completes a transition that responds to or requests an SA INIT exchange
  */
transition_return_t ike_statem_send_sa_init_msg(ike_statem_session_t *session, payload_arg_t *payload_arg, ike_payload_ike_hdr_t *ike_hdr, spd_proposal_tuple_t *offer)
{
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
  ike_statem_write_sa_payload(payload_arg, offer/* (spd_proposal_tuple_t *) CURRENT_IKE_PROPOSAL */, 0); 
  
  // Start KE payload
  ike_payload_generic_hdr_t *ke_genpayloadhdr = (ike_payload_generic_hdr_t *) payload_arg->start;
  SET_GENPAYLOADHDR(ke_genpayloadhdr, payload_arg, IKE_PAYLOAD_KE);
  
  ike_payload_ke_t *ke = (ike_payload_ke_t *) payload_arg->start;
  ke->dh_group_num = uip_htons(SA_IKE_MODP_GROUP);
  ke->clear = 0;

  // Write key exchange data (varlen)
  // (Note: We cast the first arg of ecdh_enc...() in the firm belief that payload_arg->start is at a 4 byte alignment)
	PRINTF(IPSEC_IKE "Computes and encodes public ECC Diffie Hellman key\n");
	payload_arg->start = ecdh_encode_public_key((uint32_t *) (payload_arg->start + sizeof(ike_payload_ke_t)), session->ephemeral_info->my_prv_key);
  ke_genpayloadhdr->len = uip_htons(payload_arg->start - (uint8_t *) ke_genpayloadhdr);
  // End KE payload
  
  // Start nonce payload
  ike_payload_generic_hdr_t *ninr_genpayloadhdr;
  SET_GENPAYLOADHDR(ninr_genpayloadhdr, payload_arg, IKE_PAYLOAD_NiNr);

  // Write nonce
  random_ike(payload_arg->start, IKE_PAYLOAD_MYNONCE_LEN, session->ephemeral_info->my_nonce_seed);
  MEMPRINTF("My nonce", payload_arg->start, IKE_PAYLOAD_MYNONCE_LEN);
  payload_arg->start += IKE_PAYLOAD_MYNONCE_LEN;
  ninr_genpayloadhdr->len = uip_htons(payload_arg->start - (uint8_t *) ninr_genpayloadhdr);
  // End nonce payload
  
  // Wrap up the IKE header and exit state
  ((ike_payload_ike_hdr_t *) msg_buf)->len = uip_htonl(payload_arg->start - msg_buf);
  SET_NO_NEXT_PAYLOAD(payload_arg);

  return payload_arg->start - msg_buf;
}


state_return_t ike_statem_parse_auth_msg(ike_statem_session_t *session)
{
  ike_payload_ike_hdr_t *ike_hdr = (ike_payload_ike_hdr_t *) msg_buf;  
  ike_id_payload_t *id_data = NULL;
  uint8_t id_datalen;
  ike_payload_auth_t *auth_payload = NULL;
  uint8_t transport_mode_not_accepted = 1;
  
  // Traffic selector
  ike_ts_t *tsi = NULL, *tsr = NULL;
  int16_t ts_count = -1;
  
  // Child SAs
  uint32_t time = clock_time();
  sad_entry_t *outgoing_sad_entry = sad_create_outgoing_entry(time);
  sad_entry_t *incoming_sad_entry = sad_create_incoming_entry(time);

  if (outgoing_sad_entry == NULL || incoming_sad_entry == NULL) {
		PRINTF(IPSEC_IKE_ERROR "Couldn't create SAs\n");
		goto memory_fail;
	}

  uint8_t *ptr = msg_buf + sizeof(ike_payload_ike_hdr_t);
  uint8_t *end = msg_buf + uip_datalen();
  notify_msg_type_t fail_notify_type = 0;
  ike_payload_generic_hdr_t *sa_payload = NULL;
  ike_payload_type_t payload_type = ike_hdr->next_payload;
  while (ptr < end) { // Payload loop
    const ike_payload_generic_hdr_t *genpayloadhdr = (const ike_payload_generic_hdr_t *) ptr;
    const uint8_t *payload_start = (uint8_t *) genpayloadhdr + sizeof(ike_payload_generic_hdr_t);
    
    PRINTF("Next payload is %u, %u bytes remaining\n", payload_type, uip_datalen() - (ptr - msg_buf));
    switch (payload_type) {
      case IKE_PAYLOAD_SK:
      if ((end -= ike_statem_unpack_sk(session, (ike_payload_generic_hdr_t *) genpayloadhdr)) == 0) {
        PRINTF(IPSEC_IKE_ERROR "SK payload: Integrity check of peer's message failed\n");
        fail_notify_type = IKE_PAYLOAD_NOTIFY_INVALID_SYNTAX;
        goto fail;
      }
      break;
      
      case IKE_PAYLOAD_N:
      {
        ike_payload_notify_t *notify = (ike_payload_notify_t *) payload_start;
        if (uip_ntohs(notify->notify_msg_type) == IKE_PAYLOAD_NOTIFY_USE_TRANSPORT_MODE)
          transport_mode_not_accepted = 0;
        if (ike_statem_handle_notify(notify))
          goto fail;
      }
      break;
      
      case IKE_PAYLOAD_IDi:
      case IKE_PAYLOAD_IDr:
      id_data = (ike_id_payload_t *) payload_start;
      id_datalen = uip_ntohs(genpayloadhdr->len) - sizeof(ike_payload_generic_hdr_t);
      break;
      
      case IKE_PAYLOAD_AUTH:
      MEMPRINTF("auth payload", genpayloadhdr, uip_ntohs(genpayloadhdr->len));
      auth_payload = (ike_payload_auth_t *) ((uint8_t *) genpayloadhdr + sizeof(ike_payload_generic_hdr_t));
      PRINTF("auth_payload: %p\n", auth_payload);
      
      if (auth_payload->auth_type != IKE_AUTH_SHARED_KEY_MIC) {
        PRINTF(IPSEC_IKE_ERROR "Peer using authentication type %u instead of pre-shared key authentication\n", auth_payload->auth_type);
        fail_notify_type = IKE_PAYLOAD_NOTIFY_AUTHENTICATION_FAILED;
        goto fail;
      }
      break;

      case IKE_PAYLOAD_SA:
      /**
        * Assert that the responder's child offer is a subset of that of ours
        */
      sa_payload = (ike_payload_generic_hdr_t *) genpayloadhdr;
      break;
      
      case IKE_PAYLOAD_TSi:
      case IKE_PAYLOAD_TSr:
      {
        ike_payload_ts_t *ts_payload = (ike_payload_ts_t *) payload_start;
        if (payload_type == IKE_PAYLOAD_TSr)
          tsr = (ike_ts_t *) (payload_start + sizeof(ike_payload_ts_t));
        else
          tsi = (ike_ts_t *) (payload_start + sizeof(ike_payload_ts_t));
                  
        // ts_count is the fewest number of TS selectors in TSi and TSr
        if (ts_count == -1 || ts_payload->number_of_ts < ts_count)
          ts_count = ts_payload->number_of_ts;        
      }
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

      if (genpayloadhdr->clear) {
        PRINTF(IPSEC_IKE_ERROR "Encountered an unknown critical payload\n");
        fail_notify_type = IKE_PAYLOAD_NOTIFY_UNSUPPORTED_CRITICAL_PAYLOAD;        
        goto fail;
      }
      else
        PRINTF(IPSEC_IKE "Ignoring unknown non-critical payload of type %u\n", payload_type);
      // Info: Ignored unknown payload
    }

    ptr = (uint8_t *) genpayloadhdr + uip_ntohs(genpayloadhdr->len);
    payload_type = genpayloadhdr->next_payload;
  } // End payload loop

  if (payload_type != IKE_PAYLOAD_NO_NEXT || sa_payload == NULL) {
    PRINTF(IPSEC_IKE_ERROR "Could not parse peer message.\n");
    fail_notify_type = IKE_PAYLOAD_NOTIFY_INVALID_SYNTAX;
    goto fail;
  }
  
  /**
    * Assert that transport mode was accepted
    */
  if (transport_mode_not_accepted) {
    PRINTF(IPSEC_IKE_ERROR "Peer did not accept transport mode child SA\n");
    fail_notify_type = IKE_PAYLOAD_NOTIFY_NO_PROPOSAL_CHOSEN;
    goto fail;
  }
  
  /**
    * Assert AUTH data
    */
  if (id_data == NULL || auth_payload == NULL) {
    PRINTF(IPSEC_IKE_ERROR "IDr or AUTH payload is missing\n");
    fail_notify_type = IKE_PAYLOAD_NOTIFY_AUTHENTICATION_FAILED;
    goto fail;
  }
  {
    uint8_t responder_signed_octets[session->ephemeral_info->peer_first_msg_len + session->ephemeral_info->peernonce_len + SA_PRF_OUTPUT_LEN(session)];
    
    uint16_t responder_signed_octets_len = ike_statem_get_authdata(session, 0 /* Peer's signed octets */, responder_signed_octets, id_data, id_datalen);
    uint8_t mac[SA_PRF_OUTPUT_LEN(session)];
    
    /**
      * AUTH = prf( prf(Shared Secret, "Key Pad for IKEv2"), <InitiatorSignedOctets>)
      */
    prf_data_t auth_data = {
      .out = mac,
      .data = responder_signed_octets,
      .datalen = responder_signed_octets_len
    };  
    auth_psk(session->sa.prf, &auth_data);

    if (memcmp(mac, ((uint8_t *) auth_payload) + sizeof(ike_payload_auth_t), sizeof(mac))) {
      PRINTF(IPSEC_IKE_ERROR "AUTH data mismatch\n");
      fail_notify_type = IKE_PAYLOAD_NOTIFY_AUTHENTICATION_FAILED;
      goto fail;
    }
    PRINTF(IPSEC_IKE "Peer successfully authenticated\n");
  }
  
  
  /**
    * Assert that traffic descriptors are acceptable and find matching SPD entry (responder)
    */
  int16_t ts = -1;
  if (IKE_STATEM_IS_INITIATOR(session)) {
    // If we're the initiator, the responder's TS offer must be a subset of our original offer derived from the SPD entry
    if (ts_count == 1 && selector_is_superset_of_tspair(&session->ephemeral_info->spd_entry->selector, &tsi[0], &tsr[0]))
      ts = 0; // The peer's traffic selector matched our original offer. Continue.
  }
  else {
    // We're the responder. Find the SPD entry that matches the initiator's TS offer
    for (ts = ts_count - 1; ts >= 0; --ts) {
      spd_entry_t *spd_entry = spd_get_entry_by_tspair(&tsr[ts] /* me */, &tsi[ts] /* peer */);
      if (spd_entry != NULL && spd_entry->proc_action == SPD_ACTION_PROTECT) {
        // Found an SPD entry that requires protection for this traffic
        session->ephemeral_info->spd_entry = spd_entry;
        session->ephemeral_info->my_ts_offer_addr_set.peer_addr_from = session->ephemeral_info->my_ts_offer_addr_set.peer_addr_to = &session->peer;
        ts_pair_to_addr_set(&session->ephemeral_info->my_ts_offer_addr_set, &tsr[ts], &tsi[ts]);
        break;
      }
    }
  }
  if (ts < 0) {
    PRINTF(IPSEC_IKE_ERROR "Peer's Traffic Selectors are unacceptable\n");
    fail_notify_type = IKE_PAYLOAD_NOTIFY_TS_UNACCEPTABLE;
    goto fail;
  }

  /**
    * Now that we've found the right SPD entry, we know what Child SA offer to use
    */
  if (ike_statem_parse_sa_payload(session->ephemeral_info->spd_entry->offer, 
                                  sa_payload,
                                  0,
                                  NULL,
                                  /* incoming_sad_entry */ outgoing_sad_entry,
                                  session->ephemeral_info->child_proposal_reply)) {
    PRINTF(IPSEC_IKE_ERROR "The peer's child SA offer was unacceptable\n");
    fail_notify_type = IKE_PAYLOAD_NOTIFY_NO_PROPOSAL_CHOSEN;
    goto fail;
  }
  
  // Set incoming SAD entry
  session->ephemeral_info->peer_child_spi = outgoing_sad_entry->spi;  // For use in the next response
  incoming_sad_entry->spi = session->ephemeral_info->my_child_spi;
  incoming_sad_entry->sa.proto = outgoing_sad_entry->sa.proto;
  incoming_sad_entry->sa.encr = outgoing_sad_entry->sa.encr;
  incoming_sad_entry->sa.encr_keylen = outgoing_sad_entry->sa.encr_keylen;
  incoming_sad_entry->sa.integ = outgoing_sad_entry->sa.integ;
  PRINTF(IPSEC_IKE "The peer's proposal was accepted\n");

  /**
    * Set traffic descriptors for SAD entries
    */
  // Fn: ts_pair_to_addr_set, addr_set_is_a_subset_of_addr_set, (addr_set_to_ts_pair in the future)
  // FIX: Security: Check that the TSs we receive from the peer are a subset of our offer
  outgoing_sad_entry->traffic_desc.peer_addr_from = outgoing_sad_entry->traffic_desc.peer_addr_to = &outgoing_sad_entry->peer;
  incoming_sad_entry->traffic_desc.peer_addr_from = incoming_sad_entry->traffic_desc.peer_addr_to = &incoming_sad_entry->peer;
  
  ike_ts_t *ts_me, *ts_peer;
  if (IKE_STATEM_IS_INITIATOR(session)) {
    ts_me = &tsi[ts];
    ts_peer = &tsr[ts];
  }
  else {
    ts_me = &tsr[ts];
    ts_peer = &tsi[ts];
  }
  
  ts_pair_to_addr_set(&outgoing_sad_entry->traffic_desc, ts_me, ts_peer);
  ts_pair_to_addr_set(&incoming_sad_entry->traffic_desc, ts_me, ts_peer);

  PRINTF("SELECTED TRAFFIC SELECTORS index %hd:\n", ts);
  PRINTTSPAIR(ts_me, ts_peer);

  /**
    * Get Child SA keying material as outlined in section 2.17
    *
    *     KEYMAT = prf+(SK_d, Ni | Nr)
    *
    */
  ike_statem_get_child_keymat(session, &incoming_sad_entry->sa, &outgoing_sad_entry->sa);
  
  PRINTF("===== Registered outgoing Child SA =====\n");
  PRINTSADENTRY(outgoing_sad_entry);
  PRINTF("===== Registered incoming Child SA =====\n");
  PRINTSADENTRY(incoming_sad_entry);
  PRINTF("========================================\n");
  
  return STATE_SUCCESS;
  
  fail:
  sad_remove_outgoing_entry(outgoing_sad_entry);
  sad_remove_incoming_entry(incoming_sad_entry);
	memory_fail:
  ike_statem_send_single_notify(session, fail_notify_type);
  return STATE_FAILURE;
}


transition_return_t ike_statem_send_auth_msg(ike_statem_session_t *session, payload_arg_t *payload_arg, uint32_t child_sa_spi, const spd_proposal_tuple_t *sai2_offer, const ipsec_addr_set_t *ts_instance_addr_set)
{
  // Write a template of the SK payload for later encryption
  ike_payload_generic_hdr_t *sk_genpayloadhdr = (ike_payload_generic_hdr_t *) payload_arg->start;
  ike_statem_prepare_sk(payload_arg);

  /**
    * ID payload. We use the e-mail address type of ID
    */
  ike_payload_generic_hdr_t *id_genpayloadhdr = (ike_payload_generic_hdr_t *) payload_arg->start;
  if (IKE_STATEM_IS_INITIATOR(session))
    ike_statem_set_id_payload(payload_arg, IKE_PAYLOAD_IDi);
  else
    ike_statem_set_id_payload(payload_arg, IKE_PAYLOAD_IDr);
  
  ike_id_payload_t *id_payload = (ike_id_payload_t *) ((uint8_t *) id_genpayloadhdr + sizeof(ike_payload_generic_hdr_t));
  
  /**
    * Write the AUTH payload (section 2.15)
    *
    * Details depends on the type of AUTH Method specified.
    */
  ike_payload_generic_hdr_t *auth_genpayloadhdr;
  SET_GENPAYLOADHDR(auth_genpayloadhdr, payload_arg, IKE_PAYLOAD_AUTH);
  ike_payload_auth_t *auth_payload = (ike_payload_auth_t *) payload_arg->start;
  auth_payload->auth_type = IKE_AUTH_SHARED_KEY_MIC;
  payload_arg->start += sizeof(ike_payload_auth_t);
  
  uint8_t *signed_octets = payload_arg->start + SA_PRF_MAX_OUTPUT_LEN;
  uint16_t signed_octets_len = ike_statem_get_authdata(session, 1, signed_octets, id_payload, uip_ntohs(id_genpayloadhdr->len) - sizeof(ike_payload_generic_hdr_t));
  
  /**
    * AUTH = prf( prf(Shared Secret, "Key Pad for IKEv2"), <InitiatorSignedOctets>)
    */
  prf_data_t auth_data = {
    .out = payload_arg->start,
    .data = signed_octets,
    .datalen = signed_octets_len
  };
  auth_psk(session->sa.prf, &auth_data);
  payload_arg->start += SA_PRF_OUTPUT_LEN(session);
  auth_genpayloadhdr->len = uip_htons(payload_arg->start - (uint8_t *) auth_genpayloadhdr); // Length of the AUTH payload

  /**
    * Write notification requesting the peer to create transport mode SAs
    */
  ike_statem_write_notification(payload_arg, SA_PROTO_IKE, 0, IKE_PAYLOAD_NOTIFY_USE_TRANSPORT_MODE, NULL, 0);

  /**
    * Write SAi2 (offer for the child SA)
    */
  ike_statem_write_sa_payload(payload_arg, sai2_offer, child_sa_spi);

  /**
    * The TS payload is decided by the triggering packet's header and the policy that applies to it
    *
    * Read more at "2.9.  Traffic Selector Negotiation" p. 40
    */
  PRINTF("Peer port 7890: %u\n", ts_instance_addr_set->peer_port_from);
  ike_statem_write_tsitsr(payload_arg, ts_instance_addr_set);

  // Protect the SK payload. Write trailing fields.
  ike_statem_finalize_sk(payload_arg, sk_genpayloadhdr, payload_arg->start - (((uint8_t *) sk_genpayloadhdr) + sizeof(ike_payload_generic_hdr_t)));

  return uip_ntohl(((ike_payload_ike_hdr_t *) msg_buf)->len);  // Return written length
}


/**
  * Parse an SA INIT message
  */
state_return_t ike_statem_parse_sa_init_msg(ike_statem_session_t *session, ike_payload_ike_hdr_t *ike_hdr, spd_proposal_tuple_t *accepted_offer)
{
  // session->cookie_payload = NULL; // Reset the cookie data (if it has been used)

  // Store a copy of this first message from the peer for later use
  // in the autentication calculations.
  COPY_FIRST_MSG(session, ike_hdr);
  
  // We process the payloads one by one
  uint8_t *peer_pub_key = NULL;
  uint16_t ke_dh_group = 0;  // 0 is NONE according to IANA's IKE registry
  uint8_t *ptr = msg_buf + sizeof(ike_payload_ike_hdr_t);
  uint8_t *end = msg_buf + uip_datalen();
  ike_payload_type_t payload_type = ike_hdr->next_payload;
  while (ptr < end) { // Payload loop
    const ike_payload_generic_hdr_t *genpayloadhdr = (const ike_payload_generic_hdr_t *) ptr;
    const uint8_t *payload_start = (uint8_t *) genpayloadhdr + sizeof(ike_payload_generic_hdr_t);
    const uint8_t *payload_end = (uint8_t *) genpayloadhdr + uip_ntohs(genpayloadhdr->len);
    ike_payload_ke_t *ke_payload;
    
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
      if (ike_statem_parse_sa_payload((spd_proposal_tuple_t *) CURRENT_IKE_PROPOSAL, 
                                      (ike_payload_generic_hdr_t *) genpayloadhdr, 
                                      ke_dh_group,
                                      &session->sa,
                                      NULL,
                                      accepted_offer)) {
        PRINTF(IPSEC_IKE "The peer's offer was unacceptable\n");
        return 0;
      }
      
      PRINTF(IPSEC_IKE "Peer proposal accepted\n");
      break;
      
      case IKE_PAYLOAD_NiNr:
      // This is the responder's nonce
      session->ephemeral_info->peernonce_len = payload_end - payload_start;
      memcpy(&session->ephemeral_info->peernonce, payload_start, session->ephemeral_info->peernonce_len);
      PRINTF(IPSEC_IKE "Parsed %u B long nonce from the peer\n", session->ephemeral_info->peernonce_len);
      MEMPRINTF("Peer's nonce", session->ephemeral_info->peernonce, session->ephemeral_info->peernonce_len);
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
        PRINTF(IPSEC_IKE "KE payload: Using group DH no. %u\n", ke_dh_group);
      }
      else {
        // DH group has been assigned since we've already processed the SA
        if (session->sa.dh != uip_ntohs(ke_payload->dh_group_num)) {
          PRINTF(IPSEC_IKE_ERROR "DH group of the accepted proposal doesn't match that of the KE's.\n");
          return 0;
        }
        PRINTF(IPSEC_IKE "KE payload: Using DH group no. %u\n", session->sa.dh);
      }
      
      // Store the address to the beginning of the peer's public key
      peer_pub_key = ((uint8_t *) ke_payload) + sizeof(ike_payload_ke_t);
      break;
      
      case IKE_PAYLOAD_N:
      if (ike_statem_handle_notify((ike_payload_notify_t *) payload_start))
        return 0;
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

      if (genpayloadhdr->clear) {
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
    PRINTF(IPSEC_IKE_ERROR "Unexpected end of peer's message.\n");
    return 0;
  }

  /**
    * Generate keying material for the IKE SA.
    * See section 2.14 "Generating Keying Material for the IKE SA"
    */
  ike_statem_get_ike_keymat(session, peer_pub_key);

  // Set our child SPI. To be used during the AUTH exchange.
  session->ephemeral_info->my_child_spi = SAD_GET_NEXT_SAD_LOCAL_SPI;
  
  return 1;
}


/**
  * Take the offer and write the corresponding SA payload to memory starting at payload_arg->start.
  * Handles IKE SA- as well as Child SA-offers.
  *
  * \parameter payload_arg Payload argument
  * \parameter offer The offer chain. Probably one from spd_conf.c.
  * \parameter spi The SPI of the offer's proposals (We only support one SPI per offer. Nothing tells us that this is illegal.)
  */
void ike_statem_write_sa_payload(payload_arg_t *payload_arg, const spd_proposal_tuple_t *offer, uint32_t spi)
{
  // Write the SA payload
  ike_payload_generic_hdr_t *sa_genpayloadhdr = (ike_payload_generic_hdr_t *) payload_arg->start;
  SET_GENPAYLOADHDR(sa_genpayloadhdr, payload_arg, IKE_PAYLOAD_SA);
  
  // Loop over the offers associated with this policy
  uint8_t *ptr = payload_arg->start;
  uint8_t numtransforms = 0;
  
  ike_payload_transform_t *transform = NULL;
  ike_payload_proposal_t *proposal = NULL;
  uint8_t n = 0;
  uint8_t proposal_number = 1;
  do {  // Loop over the offer's tuples
//    PRINTF("WRITE_SA_PAYLOAD: Offer type: %u\n", offer[n].type);
    switch(offer[n].type) {
        
      case SA_CTRL_NEW_PROPOSAL:
      case SA_CTRL_END_OF_OFFER:

      /**
        * Before writing the new proposal we'll set the length of the last
        */
      if (proposal != NULL) {
        proposal->proposal_len = uip_htons(ptr - (uint8_t *) proposal);
        proposal->numtransforms = numtransforms;
        
        // There's an invariant in spd.h stating that a proposal must contain at least one transforms.
        // Therefore, we assume that at least one transform has been written to the payload.
        transform->last_more = IKE_PAYLOADFIELD_TRANSFORM_LAST;
      }
      
      if (offer[n].type == SA_CTRL_END_OF_OFFER)
        break;
      
      proposal = (ike_payload_proposal_t *) ptr;
      proposal->last_more = IKE_PAYLOADFIELD_PROPOSAL_MORE;
      proposal->clear = 0U;

      proposal->proposal_number = proposal_number;
      proposal->proto_id = offer[n].value;


      ++proposal_number;
      ptr += sizeof(ike_payload_proposal_t);
      
      // There are some differences between the IKE protocol and the other ones
      if (proposal->proto_id == SA_PROTO_IKE) {
        if (spi) {
          proposal->spi_size = 8;
          *((uint32_t *) ptr) = 0U;
          *((uint32_t *) ptr + 4) = spi;
          ptr += 8;
        }
        else {
          // This case will occur whenever we negotiate the first IKE
          // p.79: "For an initial IKE SA negotiation, this field MUST be zero"
          proposal->spi_size = 0U;
        }
        numtransforms = 0;
      }
      else { // AH and ESP
        proposal->spi_size = 4;
        *((uint32_t *) ptr) = spi;
        ptr += 4;
        
        // We don't support ESNs. Start our offer with a plain no.
        transform = (ike_payload_transform_t *) ptr;
        transform->last_more = IKE_PAYLOADFIELD_TRANSFORM_MORE;
        transform->type = SA_CTRL_TRANSFORM_TYPE_ESN;
        transform->clear1 = transform->clear2 = 0U;
        transform->len = uip_htons(sizeof(ike_payload_transform_t));
        transform->id = uip_htons(SA_ESN_NO);
        ptr += sizeof(ike_payload_transform_t);
        numtransforms = 1;
      }
      break;
      
      case SA_CTRL_TRANSFORM_TYPE_ENCR:   // Encryption Algorithm (ESP, IKE)      
      case SA_CTRL_TRANSFORM_TYPE_PRF:    // Pseudorandom function (IKE)
      case SA_CTRL_TRANSFORM_TYPE_INTEG:  // Integrity Algorithm (IKE, AH, ESP (optional))
      case SA_CTRL_TRANSFORM_TYPE_DH:     // Diffie-Hellman group (IKE, AH (optional), ESP (optional))
      transform = (ike_payload_transform_t *) ptr;
      transform->last_more = IKE_PAYLOADFIELD_TRANSFORM_MORE;
      transform->type = offer[n].type;
      transform->clear1 = transform->clear2 = 0U;
      transform->id = uip_htons(offer[n].value);
      ptr += sizeof(ike_payload_transform_t);

      // Loop over any attributes associated with this transform
      // Value type: Key length of encryption algorithm
      uint8_t j = n + 1;
      while (offer[j].type == SA_CTRL_ATTRIBUTE_KEY_LEN) {
        // The only attribute defined in RFC 5996 is Key Length (p. 84)
        ike_payload_attribute_t *attrib = (ike_payload_attribute_t *) ptr;
        attrib->af_attribute_type = IKE_PAYLOADFIELD_ATTRIB_VAL;
        attrib->attribute_value = uip_htons(offer[j].value << 3); // Multiply offer->value by 8 to make it into bits
  
        ptr += sizeof(ike_payload_attribute_t);
        j++;
        n++;
      }
      
      transform->len = uip_htons(ptr - (uint8_t *) transform);
      ++numtransforms;
      break;
      
      default:
      PRINTF(IPSEC_IKE_ERROR "ike_statem_write_sa_payload: Unexpected SA_CTRL\n");
    } // End switch (offer)
  } while(offer[n++].type != SA_CTRL_END_OF_OFFER); // End while (offer)
    
  // Set the length of the offer in the generic payload header and
  // mark the last proposal as the last.
  proposal->last_more = IKE_PAYLOADFIELD_PROPOSAL_LAST;
  sa_genpayloadhdr->len = uip_htons(ptr - (uint8_t *) sa_genpayloadhdr);
    
  // End of SA payload
  payload_arg->start = ptr;
}


/**
  * Två fall:
  * peer			          me
  * responder SA(1) -> initiator offer (n): set transforms in SA, return subset
  * initiator SA(n) -> responder offer (n): set transforms in SA, return subset
  */
int8_t ike_statem_parse_sa_payload(const spd_proposal_tuple_t *my_offer, 
                                ike_payload_generic_hdr_t *sa_payload_hdr, 
                                uint8_t ke_dh_group,
                                sa_ike_t *ike_sa,
                                sad_entry_t *sad_entry,
                                spd_proposal_tuple_t *accepted_transform_subset)
{
  
  uint8_t ike = (ike_sa != NULL);
  uint8_t required_transforms;
  if (ike)
    required_transforms = 4; // Integ, encr, dh, prf
  else
    required_transforms = 2; // Integ, encr
  
  // Structure for storing candidate SA settings
  uint8_t candidates[10];       // 10 is arbitrary, but enough
  uint8_t candidate_keylen = 0;
  uint8_t acc_proposal_ctr;
  uint32_t candidate_spi = 0;
  ike_payload_proposal_t *peerproposal = (ike_payload_proposal_t *) (((uint8_t *) sa_payload_hdr) + sizeof(ike_payload_generic_hdr_t));
  
  // (#1) Loop over the proposals in the peer's offer
  while((uint8_t *) peerproposal < ((uint8_t *) sa_payload_hdr) + uip_ntohs(sa_payload_hdr->len)) {
//    PRINTF(IPSEC_IKE "#1 Looking at peerproposal %p\n", peerproposal);

    // Assert proposal properties
    if (ike && (peerproposal->proto_id != SA_PROTO_IKE || peerproposal->spi_size != 0)) {
      PRINTF(IPSEC_IKE "#1 Rejecting non-IKE proposal\n");
      goto next_peerproposal;
    }
    if (!ike && (peerproposal->proto_id != SA_PROTO_ESP || peerproposal->spi_size != 4)) {
      PRINTF(IPSEC_IKE "#1 Rejecting non-ESP proposal\n");
      goto next_peerproposal;
    }
    
    candidate_spi = *((uint32_t *) (((uint8_t *) peerproposal) + sizeof(ike_payload_proposal_t)));
    
    const spd_proposal_tuple_t *mytuple = my_offer;
    accepted_transform_subset[0].type = SA_CTRL_NEW_PROPOSAL;
    if (ike)
      accepted_transform_subset[0].value = SA_PROTO_IKE;
    else
      accepted_transform_subset[0].value = SA_PROTO_ESP;
    
    // (#2) Loop over my proposals and see if any of them is a superset of this peer's current proposal
    while (mytuple->type != SA_CTRL_END_OF_OFFER) {
      // We're now at the beginning of one of our offers.
//      PRINTF("#2 At the beginning of one our offers\n");
            
      ++mytuple; // Jump the SA_CTRL_NEW_PROPOSAL
      memset(candidates, 0, sizeof(candidates));
      uint8_t accepted_transforms = 0;  // Number of accepted transforms
      acc_proposal_ctr = 0;
      
      // (#3) Loop over this proposal in my offer
      while (mytuple->type != SA_CTRL_END_OF_OFFER && mytuple->type != SA_CTRL_NEW_PROPOSAL) {        
        // Does this transform have an attribute?

//        PRINTF(IPSEC_IKE "\n#3 Looking at mytuple->type %u mytuple->value %u\n", mytuple->type, mytuple->value);
        uint8_t my_keylen = 0;
        if ((mytuple + 1)->type == SA_CTRL_ATTRIBUTE_KEY_LEN)
          my_keylen = (mytuple + 1)->type;
        
        ike_payload_transform_t *peertransform = (ike_payload_transform_t *) ((uint8_t *) peerproposal + sizeof(ike_payload_proposal_t) + peerproposal->spi_size);
        
        // (#4) Loop over the peer's proposal and see if this transform of mine can be found
        while((uint8_t *) peertransform < (uint8_t *) peerproposal + uip_ntohs(peerproposal->proposal_len)) {
//          PRINTF(IPSEC_IKE "#4 peertransform->type %u. mytuple->type (%u), peertransform->id: %u. mytuple->value: %u \n", peertransform->type, mytuple->type, uip_ntohs(peertransform->id), mytuple->type);
//          PRINTF(IPSEC_IKE "#4 peertransform->type %u, peertransform->id: %u\n", peertransform->type, uip_ntohs(peertransform->id));

          // Is this is DH group transform; if so, is acceptable with our requirements?
          if (ke_dh_group && 
              peertransform->type == SA_CTRL_TRANSFORM_TYPE_DH &&
              uip_ntohs(peertransform->id) != ke_dh_group) {
            PRINTF(IPSEC_IKE "#4 Peer proposal with DH group that differs from that of the KE payload. Rejecting.\n");
            goto next_peertransform;
          }
          
          // Check for extended sequence number
          if (peertransform->type == SA_CTRL_TRANSFORM_TYPE_ESN && uip_ntohs(peertransform->id) != SA_ESN_NO) {
            PRINTF(IPSEC_IKE "#4 Peer proposal using extended sequence number found. Rejecting.\n");
            goto next_peertransform;
          }

          if (!candidates[peertransform->type] &&                 // (that we haven't accepted a transform of this type!)
              peertransform->type == mytuple->type &&
              uip_ntohs(peertransform->id) == mytuple->value) {
          
            // Peer and I have the same type and value
            if (my_keylen) {
              // I have a keylen requirement. Does it fit that of the peer?
              if (uip_ntohs(peertransform->len) != sizeof(ike_payload_transform_t)) {
                // The peer have included an attribtue as well
                ike_payload_attribute_t *peer_attrib = (ike_payload_attribute_t *) ((uint8_t *) peertransform + sizeof(ike_payload_transform_t));
                
                if (uip_ntohs(peer_attrib->af_attribute_type) != UIP_HTONS(IKE_PAYLOADFIELD_ATTRIB_VAL)) {
                  PRINTF(IPSEC_IKE "#4 Error: Unrecognized attribute type: %x (UIP_HTONS(IKE_PAYLOADFIELD_ATTRIB_VAL): %x)\n", uip_ntohs(peer_attrib->af_attribute_type), UIP_HTONS(IKE_PAYLOADFIELD_ATTRIB_VAL));
                  goto next_peertransform;
                }
                else {
                  // This is a keylen attribute
                  if (uip_ntohs(peer_attrib->attribute_value) < my_keylen) {
                    // The peer requested a shorter key length. We cannot accept this transform!
                    goto next_peertransform;
                  }
                  
                  // Accept the candidate keylen (which might be longer than the one in our proposal)
                  candidate_keylen =  uip_ntohs(peer_attrib->attribute_value) >> 3; // Divide by eight
                }
              }
              else
                goto next_peertransform;                
            }
            // We end up here if we've accepted the transform
//            PRINTF(IPSEC_IKE "#4 Is candidate\n");              
            
            // Add the transform to the resulting output offer
            ++acc_proposal_ctr;
            memcpy(&accepted_transform_subset[acc_proposal_ctr], mytuple, sizeof(spd_proposal_tuple_t));
            if (candidate_keylen && mytuple->type == SA_CTRL_TRANSFORM_TYPE_ENCR) {
              if (acc_proposal_ctr >= IKE_REPLY_MAX_PROPOSAL_TUPLES)
                return 1;
            
              accepted_transform_subset[++acc_proposal_ctr].type = SA_CTRL_ATTRIBUTE_KEY_LEN;
              accepted_transform_subset[acc_proposal_ctr].value = candidate_keylen;
            }
            
            // Set the SA
            candidates[mytuple->type] = mytuple->value;
            ++accepted_transforms;
            if (accepted_transforms == required_transforms)
              goto found_acceptable_proposal;
          }
          
          // Forward to the next transform (jumping any attributes)
          next_peertransform:
          peertransform = (ike_payload_transform_t *) (((uint8_t *) peertransform) + uip_ntohs(peertransform->len));
        } // End #4
        
        if (my_keylen)
          mytuple += 2;
        else
          ++mytuple;
      } // End #3
    }
    
    /**
      * If we end here we did so because this proposal from the peer didn't match any of ours
      * Go to the next proposal
      */
    next_peerproposal:
    peerproposal = (ike_payload_proposal_t *) (((uint8_t *) peerproposal) + uip_ntohs(peerproposal->proposal_len));
  }
  // We didn't find an acceptable proposal. Leave.
  
  return 1; // Fail
  
  /**
    * We've found an acceptable proposal.
    */
  found_acceptable_proposal:
  
  accepted_transform_subset[acc_proposal_ctr + 1].type = SA_CTRL_END_OF_OFFER;

  // Set the SA
  if (ike) {
    ike_sa->encr = candidates[SA_CTRL_TRANSFORM_TYPE_ENCR];
    ike_sa->encr_keylen = candidate_keylen;
    ike_sa->integ = candidates[SA_CTRL_TRANSFORM_TYPE_INTEG];
    ike_sa->prf = candidates[SA_CTRL_TRANSFORM_TYPE_PRF];
    ike_sa->dh = candidates[SA_CTRL_TRANSFORM_TYPE_DH];
  }
  else {
    sad_entry->spi = candidate_spi;
    sad_entry->sa.proto = SA_PROTO_ESP;
    sad_entry->sa.encr = candidates[SA_CTRL_TRANSFORM_TYPE_ENCR];
    sad_entry->sa.encr_keylen = candidate_keylen;
    sad_entry->sa.integ = candidates[SA_CTRL_TRANSFORM_TYPE_INTEG];
  }
  
  return 0; // Success
}

/**
  * Helper for ike_statem_get_authdata
  */
uint32_t rerun_init_msg(uint8_t *out, uint8_t initreq, ike_statem_session_t *session)
{
  /**
    * Stash the current state
    */
    
  // Stash peer SPI
  uint32_t peer_spi_high = session->peer_spi_high;
  uint32_t peer_spi_low = session->peer_spi_low;

  if (initreq) {
    session->peer_spi_high = 0;
    session->peer_spi_low = 0;
  }
  
  // Stash my msg ID
  uint32_t my_msg_id = session->my_msg_id;

  session->my_msg_id = 0;
  
  // Buffers
  uint8_t *msg_buf_save = msg_buf;  // ike_statem_trans_initreq() writes to the address of msg_buf
  msg_buf = out;
  if (initreq)
    ike_statem_trans_initreq(session);  // Re-write our first message to assembly_start  
  else
    ike_statem_trans_initresp(session);
  
  /** 
    * Restore old state
    */
  msg_buf = msg_buf_save;
  session->peer_spi_high = peer_spi_high;
  session->peer_spi_low = peer_spi_low;
  session->my_msg_id = my_msg_id;
  
  return uip_ntohl(((ike_payload_ike_hdr_t *) out)->len);
}


/**
  * Get InitiatorSignedOctets or ResponderSignedOctets (depending on session) as described on p. 47.
  *
  * \param session      Current session
  * \param myauth       Generate my *SignedOctet (use my own RealMessage) if set to one, generate the peer's *SignedOctets (use the peer's stored RealMessage) if set to zero.
  * \param out          Address where AUTH will be written. Free space should amount to ~1 kB (depending on msg sizes etc).
  * \param id_payload   The address of the ID payload
  * \param id_len       The length of the ID payload, excluding its generic payload header
  *
  * \return length of *SignedOctets, 0 if an error occurred
  */
uint16_t ike_statem_get_authdata(ike_statem_session_t *session, const uint8_t myauth, uint8_t *out, ike_id_payload_t *id_payload, uint16_t id_payload_len)
{
  uint8_t *ptr = out;

  /**
    * There are four types of SignedOctets -strings that can be created:
    *   0. We are the responder, and we recreate the peer's InitiatorSignedOctets
    *   1. We are the responder, and we create our ResponderSignedOctets
    *   2. We are the initiator, and we recreate the peer's ResponderSignedOctets
    *   3. We are the initiator, and we create our InitiatorSignedOctets
    *
    */
  uint8_t type = 2 * (IKE_STATEM_IS_INITIATOR(session) > 0) + myauth;
  PRINTF("Type is %u, initiator: %u\n", type, IKE_STATEM_IS_INITIATOR(session));
  
  // Pack RealMessage*
  PRINTF("RealMessage1: ");

  switch (type) {
    case 0:
    PRINTF("Using peer_first_msg, len %u\n", session->ephemeral_info->peer_first_msg_len);
    memcpy(ptr, session->ephemeral_info->peer_first_msg, session->ephemeral_info->peer_first_msg_len);
    ptr += session->ephemeral_info->peer_first_msg_len;
    break;
    
    case 1:
    PRINTF("Re-running our first message's transition\n");
    ptr += rerun_init_msg(ptr, 0, session);
    break;
    
    case 2:
    PRINTF("Using peer_first_msg\n");
    memcpy(ptr, session->ephemeral_info->peer_first_msg, session->ephemeral_info->peer_first_msg_len);
    ptr += session->ephemeral_info->peer_first_msg_len;
    break;
    
    case 3:
    PRINTF("Re-running our first message's transition\n");
    ptr += rerun_init_msg(ptr, 1, session);
  }

  // Nonce(I/R)Datatop
  
  if (myauth) {
    memcpy(ptr, session->ephemeral_info->peernonce, session->ephemeral_info->peernonce_len);
    ptr += session->ephemeral_info->peernonce_len;    
  }
  else {
    random_ike(ptr, IKE_PAYLOAD_MYNONCE_LEN, session->ephemeral_info->my_nonce_seed);
    ptr += IKE_PAYLOAD_MYNONCE_LEN;
  }
  
  // MACedIDForI ( prf(SK_pi, IDType | RESERVED | InitIDData) = prf(SK_pi, RestOfInitIDPayload) )
  prf_data_t prf_data =
  {
    .out = ptr,
    .keylen = SA_PRF_PREFERRED_KEYMATLEN(session), // SK_px is always of the PRF's preferred keymat length
    .data = (uint8_t *) id_payload,
    .datalen = id_payload_len
  };
  
  MEMPRINTF("id_payload", id_payload, id_payload_len);

  /*
  0:pr
  1:pi
  2:pi
  3:pr
  */
  if (type % 3) {
    prf_data.key = session->ephemeral_info->sk_pr;
    MEMPRINTF("Using key sk_pr", prf_data.key, prf_data.keylen);
  }
  else {
    prf_data.key = session->ephemeral_info->sk_pi;
    MEMPRINTF("Using key sk_pi", prf_data.key, prf_data.keylen);
  }

  prf(session->sa.prf, &prf_data);
  ptr += SA_PRF_PREFERRED_KEYMATLEN(session);

  MEMPRINTF("*SignedOctets", out, ptr - out);
  return ptr - out;
}



/**
  * Unpacks (i.e. checks integrity and decrypts) an SK payload / IKE message. 
  *
  * \parameter session Session concerned
  * \parameter sk_genpayloadhdr The generic paylod header of the SK payload
  *
  * \return 0 if the integrity check fails. If successfull, the number of trailing bytes is returned
  */
uint8_t ike_statem_unpack_sk(ike_statem_session_t *session, ike_payload_generic_hdr_t *sk_genpayloadhdr)
{
  uint16_t integ_datalen = uip_ntohl(((ike_payload_ike_hdr_t *) msg_buf)->len) - IPSEC_ICVLEN;
  uint8_t trailing_bytes = 0;
  
  // Integrity
  if (session->sa.integ) {
    // Length of data to be integrity protected:
    // IKE header + (anything in between) + SK header + IV + data + padding + padding length field
    uint8_t expected_icv[IPSEC_ICVLEN];

    integ_data_t integ_data = {
      .type = session->sa.integ,
      .data = msg_buf,                        // The start of the data
      .datalen = integ_datalen,               // Data to be integrity protected
      .out = expected_icv          // Where the output will be written. IPSEC_ICVLEN bytes will be written.
    };
    
    if(IKE_STATEM_IS_INITIATOR(session))
      integ_data.keymat = session->sa.sk_ar;                // Address of the keying material
    else
      integ_data.keymat = session->sa.sk_ai;

    //MEMPRINTF("integ keymat", integ_data.keymat, SA_INTEG_CURRENT_KEYMATLEN(payload_arg->session));
    integ(&integ_data);                      // This will write Encrypted Payloads, padding and pad length  

    if (memcmp(expected_icv, msg_buf + integ_datalen, IPSEC_ICVLEN) != 0)
      return 0;
      
    trailing_bytes += IPSEC_ICVLEN;
  }
  
  // Confidentiality / Combined mode
  uint16_t datalen = uip_ntohs(sk_genpayloadhdr->len) - IPSEC_ICVLEN - sizeof(ike_payload_generic_hdr_t);
  
  encr_data_t encr_data = {
    .type = session->sa.encr,
    .keylen = session->sa.encr_keylen,
    .encr_data = ((uint8_t *) sk_genpayloadhdr) + sizeof(ike_payload_generic_hdr_t),
    // From the beginning of the IV to the pad length field
    .encr_datalen = datalen,
    .ip_next_hdr = NULL
  };
  
  if(IKE_STATEM_IS_INITIATOR(session))
    encr_data.keymat = session->sa.sk_er;                // Address of the keying material
  else
    encr_data.keymat = session->sa.sk_ei;
 
  //MEMPRINTF("encr_key", encr_data.keymat, 15);
  
  espsk_unpack(&encr_data); // Encrypt / combined mode
    
  // Move the data over the IV as the former's length might not be a multiple of four
  uint8_t *iv_start = (uint8_t *) sk_genpayloadhdr + sizeof(ike_payload_generic_hdr_t);
  memmove(iv_start, iv_start + sa_encr_ivlen[session->sa.encr], datalen);
  sk_genpayloadhdr->len = uip_htons(sizeof(ike_payload_generic_hdr_t));
  
  // Adjust trailing bytes
  //                IV length                       + padding         + pad length field
  trailing_bytes += sa_encr_ivlen[session->sa.encr] + encr_data.padlen +        1;
  
  return trailing_bytes;
}



/**
  * Writes a "skeleton" of the SK payload. You can continue building your message right after the
  * resulting SK payload and then finish the encryption by calling \c ike_statem_finalize_sk()
  *
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    | Next Payload  |C|  RESERVED   |         Payload Length        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                     Initialization Vector                     |
    |         (length is block size for encryption algorithm)       |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                   -- Put your IKE Payloads here --                 
  *
  * \parameter payload_arg Payload arg
  */
void ike_statem_prepare_sk(payload_arg_t *payload_arg)
{
  ike_payload_generic_hdr_t *sk_genpayloadhdr;
  SET_GENPAYLOADHDR(sk_genpayloadhdr, payload_arg, IKE_PAYLOAD_SK);

  // Generate the IV
  uint8_t n;
  for (n = 0; n < SA_ENCR_CURRENT_IVLEN(payload_arg->session); ++n)
    payload_arg->start[n] = rand16();
  payload_arg->start += n;
}


/**
  * This function completes the encryption of an SK payload and can only be 
  * called after \c ike_statem_prepare_sk()
  *
  * BEFORE
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       | Next Payload  |C|  RESERVED   |         Payload Length        |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                     Initialization Vector                     |
       |         (length is block size for encryption algorithm)       |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       ~                    Unencrypted IKE Payloads                   ~
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  *
  * AFTER
  * 
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       | Next Payload  |C|  RESERVED   |         Payload Length        |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                     Initialization Vector                     |
       |         (length is block size for encryption algorithm)       |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       ~                    Encrypted IKE Payloads                     ~
       +               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |               |             Padding (0-255 octets)            |
       +-+-+-+-+-+-+-+-+                               +-+-+-+-+-+-+-+-+
       |                                               |  Pad Length   |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       ~                    Integrity Checksum Data                    ~
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

  *
  *
  * \parameter session The session, used for fetching the encryption keys
  * \parameter sk_genpayloadhdr The generic payload header of the SK payload, as created by \c ike_statem_prepare_sk()
  * \parameter len The length of the IV + the data to be encrypted
  */
void ike_statem_finalize_sk(payload_arg_t *payload_arg, ike_payload_generic_hdr_t *sk_genpayloadhdr, uint16_t data_len)
{
  PRINTF("msg_buf: %p\n", msg_buf);
  /**
    * Before calculating the ICV value we need to set the final length
    * of the IKE message and the SK payload
    */
  SET_NO_NEXT_PAYLOAD(payload_arg);
  
  // Confidentiality / Combined mode
  encr_data_t encr_data =  {
    .type = payload_arg->session->sa.encr,
    .keylen = payload_arg->session->sa.encr_keylen,
    .integ_data = msg_buf,                    // Beginning of the ESP header (ESP) or the IKEv2 header (SK)
    .encr_data = (uint8_t *) sk_genpayloadhdr + sizeof(ike_payload_generic_hdr_t),
    .encr_datalen = data_len,                 // From the beginning of the IV to the IP next header field (ESP) or the padding field (SK).
    .ip_next_hdr = NULL
  };

  if(IKE_STATEM_IS_INITIATOR(payload_arg->session))
    encr_data.keymat = payload_arg->session->sa.sk_ei;
  else
    encr_data.keymat = payload_arg->session->sa.sk_er;                // Address of the keying material
 
  PRINTF("encr: %u\n", encr_data.type);
  MEMPRINTF("encr_key", encr_data.keymat, encr_data.keylen);
  
  espsk_pack(&encr_data); // Encrypt / combined mode
  
  // sk_len = ike_payload_generic_hdr_t size + ICV and data + pad length + pad length field + IPSEC_ICVLEN
  uint16_t sk_len = sizeof(ike_payload_generic_hdr_t) + data_len + encr_data.padlen + 1 + IPSEC_ICVLEN;
  sk_genpayloadhdr->len = uip_htons(sk_len);
  payload_arg->start = ((uint8_t *) sk_genpayloadhdr) + sk_len;
  uint32_t msg_len = payload_arg->start - msg_buf;
  PRINTF("msg_len: %u\n", msg_len);
  ((ike_payload_ike_hdr_t *) msg_buf)->len = uip_htonl(msg_len);
  PRINTF("sk_genpayloadhdr->len: %u data_len: %u\n", uip_ntohs(sk_genpayloadhdr->len), data_len);
    
  // Integrity
  if (payload_arg->session->sa.integ) {
    // Length of data to be integrity protected:
    // IKE header + (anything in between) + SK header + IV + data + padding + padding length field
    uint16_t integ_datalen = msg_len - IPSEC_ICVLEN;

    integ_data_t integ_data = {
      .type = payload_arg->session->sa.integ,
      .data = msg_buf,                        // The start of the data
      .datalen = integ_datalen,               // Data to be integrity protected
      .out = msg_buf + integ_datalen          // Where the output will be written. IPSEC_ICVLEN bytes will be written.
    };
    PRINTF("msg_buf: %p\n", msg_buf);
    PRINTF("integ_data.out: %p\n", integ_data.out);
    
    if(IKE_STATEM_IS_INITIATOR(payload_arg->session))
      integ_data.keymat = payload_arg->session->sa.sk_ai;
    else
      integ_data.keymat = payload_arg->session->sa.sk_ar;                // Address of the keying material

    MEMPRINTF("integ keymat", integ_data.keymat, SA_INTEG_CURRENT_KEYMATLEN(payload_arg->session));
    integ(&integ_data);                      // This will write Encrypted Payloads, padding and pad length  
  }
}


/**
  * Sets the Identification payload to the e-mail address defined auth.c
  */
void ike_statem_set_id_payload(payload_arg_t *payload_arg, ike_payload_type_t payload_type)
{
  ike_payload_generic_hdr_t *id_genpayloadhdr;
  SET_GENPAYLOADHDR(id_genpayloadhdr, payload_arg, payload_type);

  ike_id_payload_t *id_payload = (ike_id_payload_t *) payload_arg->start;
   /* Clear the RESERVED area */
  *((uint32_t *) id_payload) = 0;
  *((uint8_t *) id_payload) = IKE_ID_RFC822_ADDR;
  payload_arg->start += sizeof(ike_id_payload_t);
  memcpy(payload_arg->start, (uint8_t *) ike_id, sizeof(ike_id));
  payload_arg->start += sizeof(ike_id);
  id_genpayloadhdr->len = uip_htons(payload_arg->start - (uint8_t *) id_genpayloadhdr);
}

/**
  * This function decrypts an SK payload using the IKE SA's parameters and the starting address of the SK payload's generic header.
  * If the SK payload's syntax is correct and the cryptographic checksum computation matches that included in the payload, the SK payload
  * (including its generic payload header) is replaced with the decrypted IKE payloads.
  *
  * This entails that the address of the generic payload header at sk_genpayload_hdr will contain the values of the first encrypted
  * IKE payload after the call to this function has been completed.
  *
  * BEFORE
  * 
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       | Next Payload  |C|  RESERVED   |         Payload Length        |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                     Initialization Vector                     |
       |         (length is block size for encryption algorithm)       |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       ~                    Encrypted IKE Payloads                     ~
       +               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |               |             Padding (0-255 octets)            |
       +-+-+-+-+-+-+-+-+                               +-+-+-+-+-+-+-+-+
       |                                               |  Pad Length   |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       ~                    Integrity Checksum Data                    ~
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  *
  * AFTER
  *
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       | Next Payload  |C|  RESERVED   | Payload Len  (4 + IV length)  |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                     Initialization Vector                     |
       |         (length is block size for encryption algorithm)       |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       ~                    Decrypted IKE Payloads                     ~
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  *
  *
  * \parameter payload_arg The payload_arg
  * \parameter sk_genpayload_hdr The generic payload header of the SK payload.
  *
  * \return 1 upon failure, 0 upon success
  */
// uint8_t ike_statem_unpack_sk(payload_arg_t *payload_arg, ike_generic_payload_hdr_t *sk_genpayload_hdr)
// {
//   /**
//     * Verify the intergrity checksum data
//     */
//   uint8_t integ_len = SA_INTEG_CURRENT_KEYMATLEN(payload_arg->session);
//   uint8_t *integ_chksum = sk_genpayload_hdr + UIP_NTOHS(sk_genpayload_hdr->len) - integ_len;
//   uint8_t out[integ_len];
// 
//   prf_data_t data = {
//     .out = &out,
//     .outlen = integ_len,
//     .key = IKE_STATEM_GET_PEER_SK_A(payload_arg->session),
//     .keylen = integ_len,
//     .data = &udp_buf,
//     .datalen = integ_chksum - udp_buf;
//   };
//   integ(payload_arg->session->sa.integ, &data);
//     
//   // Hash computed. Assert its correctness.
//   if (memcmp(&out, integ_chksum, integ_len))
//     return 1; // Cryptographic hash mismatch
//   
//   /**
//     * Decrypt the IKE payloads
//     */
//   encr_data_t encr_data = {
//     .encr = payload_arg->session.sa.encr,                                                   // This determines transform and block size among other things
//     .start = sk_genpayload_hdr + sizeof(sk_genpayload_hdr),                                 // Address of IV. The actual data is expected to follow one block size after.
//     .datalen = UIP_NTOHS(sk_genpayload_hdr->len) - integ_len - sizeof(sk_genpayload_hdr),   // Length of the IV and the data
//     .key = IKE_STATEM_GET_PEER_SK_E(paylod_arg->session),                                   // Address of the key
//     .keylen = payload_arg->session->sa.encr_keylen                                          // Length of the key _in bytes_
//   }
//   decr(&encr_data);
// 
//   // We have now verified the Integrity Checksum and decrypted the IKE payloads.
//   // Adjust the length field of the SK payload so that it "points" to the following IKE payload.
//   sk_genpayload_hdr->len = uip_htons(sizeof(sk_genpayload_hdr) + encr_data->datalen);
// }



/**
  * Function that delivers suitable actions and suitable informational / error messages.
  * Should work for all cases
  *
  * \return 1 if the notify message implies that the peer has hung up, 0 otherwise.
  */
uint8_t ike_statem_handle_notify(ike_payload_notify_t *notify_payload)
{
  notify_msg_type_t type = uip_ntohs(notify_payload->notify_msg_type);
  
  /**
    * See payload.h for a complete list of notify message types
    */
  if (type < IKE_PAYLOAD_NOTIFY_INITIAL_CONTACT) {
    switch (type) {
      /*
      IKE_PAYLOAD_NOTIFY_UNSUPPORTED_CRITICAL_PAYLOAD = 1,
      IKE_PAYLOAD_NOTIFY_INVALID_IKE_SPI = 4,
      IKE_PAYLOAD_NOTIFY_INVALID_MAJOR_VERSION = 5,
      */    
      case IKE_PAYLOAD_NOTIFY_INVALID_SYNTAX:
      PRINTF(IPSEC_IKE_ERROR "Peer didn't recognize our message's syntax\n");
      break;
      
      case IKE_PAYLOAD_NOTIFY_INVALID_MESSAGE_ID:
      PRINTF(IPSEC_IKE_ERROR "Peer believes our message's ID is incorrect\n");
      break;
      
      /* IKE_PAYLOAD_NOTIFY_INVALID_SPI = 11, */
      case IKE_PAYLOAD_NOTIFY_NO_PROPOSAL_CHOSEN:
      PRINTF(IPSEC_IKE_ERROR "Peer didn't not accept any of our proposals\n");
      break;
      
      case IKE_PAYLOAD_NOTIFY_INVALID_KE_PAYLOAD:
      PRINTF(IPSEC_IKE_ERROR "Peer found our KE payload (public key) to be invalid\n");
      break;
      
      case IKE_PAYLOAD_NOTIFY_AUTHENTICATION_FAILED:
      PRINTF(IPSEC_IKE_ERROR "Peer could not authenticate us.\n");
      break;
      
      case IKE_PAYLOAD_NOTIFY_SINGLE_PAIR_REQUIRED:
      PRINTF("Peer requires a single pair of Traffic Selectors\n");
      break;
      
      /*
      IKE_PAYLOAD_NOTIFY_NO_ADDITIONAL_SAS = 35,
      IKE_PAYLOAD_NOTIFY_INTERNAL_ADDRESS_FAILURE = 36,
      IKE_PAYLOAD_NOTIFY_FAILED_CP_REQUIRED = 37,
      */
      
      case IKE_PAYLOAD_NOTIFY_TS_UNACCEPTABLE:
      PRINTF(IPSEC_IKE_ERROR "Peer found our Traffic Selectors to be unacceptable\n");
      break;
      
      case IKE_PAYLOAD_NOTIFY_INVALID_SELECTORS:
      PRINTF(IPSEC_IKE_ERROR "Peer found or Traffic Selectors to be invalid.\n");
      break;
      
      default:
      PRINTF(IPSEC_IKE_ERROR "Received error notify message of type no. %u\n", type);
    }
    return 1;
  }  
  else {
    // Informational types
    
    /*
    IKE_PAYLOAD_NOTIFY_TEMPORARY_FAILURE = 43,
    IKE_PAYLOAD_NOTIFY_CHILD_SA_NOT_FOUND = 44,
    */
    switch (type) {
      /*
      IKE_PAYLOAD_NOTIFY_INITIAL_CONTACT = 16384,
      IKE_PAYLOAD_NOTIFY_SET_WINDOW_SIZE = 16385,
      IKE_PAYLOAD_NOTIFY_ADDITIONAL_TS_POSSIBLE = 16386,
      IKE_PAYLOAD_NOTIFY_IPCOMP_SUPPORTED = 16387,
      IKE_PAYLOAD_NOTIFY_NAT_DETECTION_SOURCE_IP = 16388,
      IKE_PAYLOAD_NOTIFY_NAT_DETECTION_DESTINATION_IP = 16389,
      */
      
      case IKE_PAYLOAD_NOTIFY_COOKIE:
      PRINTF(IPSEC_IKE_ERROR "Peer has handed us a cookie and expects us to use it, but we can't handle cookies\n");
      return 1;      
      
      case IKE_PAYLOAD_NOTIFY_USE_TRANSPORT_MODE:
      PRINTF(IPSEC_IKE "Peer demands child SAs to use transport, not tunnel mode\n");
      break;
        
      /*
      IKE_PAYLOAD_NOTIFY_HTTP_CERT_LOOKUP_SUPPORTED = 16392,
      IKE_PAYLOAD_NOTIFY_REKEY_SA = 16393,
      IKE_PAYLOAD_NOTIFY_ESP_TFC_PADDING_NOT_SUPPORTED = 16394,
      IKE_PAYLOAD_NOTIFY_NON_FIRST_FRAGMENTS_ALSO = 16395
      */
      default:
      PRINTF(IPSEC_IKE "Received informative notify message of type no. %u\n", type);
    }
  }
  return 0;
}

/**
  * Performs the calculations as described in section 2.14
  *
    SKEYSEED = prf(Ni | Nr, g^ir)

    {SK_d | SK_ai | SK_ar | SK_ei | SK_er | SK_pi | SK_pr }
                    = prf+ (SKEYSEED, Ni | Nr | SPIi | SPIr )
  *
  * \parameter session The session concerned
  * \parameter peer_pub_key Address of the beginning of the field "Key Exchange Data" in the peer's KE payload (network byte order).
  * \return The address that follows the last byte of the nonce
  */
void ike_statem_get_ike_keymat(ike_statem_session_t *session, uint8_t *peer_pub_key)
{
  // Calculate the DH exponential: g^ir
  PRINTF(IPSEC_IKE "Calculating shared ECC Diffie Hellman secret\n");
  uint8_t gir[IKE_DH_SCALAR_LEN];
  ecdh_get_shared_secret(gir, peer_pub_key, session->ephemeral_info->my_prv_key);
  MEMPRINTF("Shared ECC Diffie Hellman secret (g^ir)", gir, IKE_DH_SCALAR_LEN);

  /**
    * The order of the strings will depend on who's the initiator. Prepare that.
    */
  uint8_t first_keylen = IKE_PAYLOAD_MYNONCE_LEN + session->ephemeral_info->peernonce_len;
  uint8_t first_key[first_keylen];

  uint8_t second_msg[IKE_PAYLOAD_MYNONCE_LEN +   // Ni or Nr
      session->ephemeral_info->peernonce_len +    // Ni or Nr 
      2 * 8   // 2 * SPI
      ];
  
  uint8_t *mynonce_start, *peernonce_start;
  uint8_t *ni_start, *nr_start, *spii_start, *spir_start;  
  if (IKE_STATEM_IS_INITIATOR(session)) {
    mynonce_start = first_key;
    peernonce_start = mynonce_start + IKE_PAYLOAD_MYNONCE_LEN;
    
    ni_start = second_msg;
    nr_start = ni_start + IKE_PAYLOAD_MYNONCE_LEN;
    spii_start = nr_start + session->ephemeral_info->peernonce_len;
    spir_start = spii_start + 8;
  }
  else {

    peernonce_start = first_key;
    mynonce_start = peernonce_start + session->ephemeral_info->peernonce_len;
    
    nr_start = second_msg;
    ni_start = nr_start + session->ephemeral_info->peernonce_len;
    spir_start = ni_start + IKE_PAYLOAD_MYNONCE_LEN;
    spii_start = spir_start + 8;
  }  
  
  /**
    * Run the first PRF operation
    
      SKEYSEED = prf(Ni | Nr, g^ir)
    *
    */
  random_ike(mynonce_start, IKE_PAYLOAD_MYNONCE_LEN, session->ephemeral_info->my_nonce_seed);
  memcpy(peernonce_start, session->ephemeral_info->peernonce, session->ephemeral_info->peernonce_len);
  PRINTF("first_keylen: %u peernonce_len: %u\n", first_keylen, session->ephemeral_info->peernonce_len);

  MEMPRINTF("Ni | Nr", first_key, first_keylen);
  
  MEMPRINTF("Shared DH secret (g^ir)", gir, IKE_DH_SCALAR_LEN);

  uint8_t skeyseed[SA_PRF_OUTPUT_LEN(session)];

  prf_data_t prf_data =
    {
      .out = skeyseed,
      .key = first_key,
      .keylen = first_keylen,
      .data = gir,
      .datalen = IKE_DH_SCALAR_LEN
    };
  prf(session->sa.prf, &prf_data);

  MEMPRINTF("SKEYSEED", skeyseed, 20);
  
  /**
    * Complete the next step:
    * 
      {SK_d | SK_ai | SK_ar | SK_ei | SK_er | SK_pi | SK_pr }
                  = prf+ (SKEYSEED, Ni | Nr | SPIi | SPIr )
    */

  /**
    * Compile the second message (Ni | Nr | SPIi | SPIr)
    */
  random_ike(ni_start, IKE_PAYLOAD_MYNONCE_LEN, session->ephemeral_info->my_nonce_seed);      
  memcpy(nr_start, session->ephemeral_info->peernonce, session->ephemeral_info->peernonce_len);
  *((uint32_t *) spii_start) = IKE_STATEM_MYSPI_GET_MYSPI_HIGH(session);
  *(((uint32_t *) spii_start) + 1) = IKE_STATEM_MYSPI_GET_MYSPI_LOW(session);
  *((uint32_t *) spir_start) = session->peer_spi_high;
  *(((uint32_t *) spir_start) + 1) = session->peer_spi_low;

  /**
    * Run the second, and last, PRF operation
    */
        
  // Set up the arguments
  sa_ike_t *sa = &session->sa;


  /**
    * Memory addresses and lengths of {SK_d | SK_ai | SK_ar | SK_ei | SK_er | SK_pi | SK_pr }
    *
    * The lengths of the fields are determined as follows:
    *   SK_a* and SK_e* are the sources of keying material for the integrity and the encryption algorithm, respectively.
    *   Therefore their lengths are determined by the choice of algorithm (made so during the first exchange, which has
    *   been completed at when this function is called)
    *
    *   SK_d (source of keying material for child SAs) and SK_p* (used during authentication) length's are of the negotiated PRF's 
    *   preferred key length. From p. 47, first paragraph:
    *     "The lengths of SK_d, SK_pi and SK_pr MUST be the preferred key length of the PRF agreed upon."
    *
    */
  uint8_t *sk_ptr[] = { sa->sk_d,                             sa->sk_ai,                        sa->sk_ar,                            sa->sk_ei,                      sa->sk_er,                        session->ephemeral_info->sk_pi,       session->ephemeral_info->sk_pr };
  uint8_t sk_len[]  = { SA_PRF_PREFERRED_KEYMATLEN(session), SA_INTEG_CURRENT_KEYMATLEN(session), SA_INTEG_CURRENT_KEYMATLEN(session), SA_ENCR_CURRENT_KEYMATLEN(session), SA_ENCR_CURRENT_KEYMATLEN(session), SA_PRF_PREFERRED_KEYMATLEN(session), SA_PRF_PREFERRED_KEYMATLEN(session) };

  prfplus_data_t prfplus_data = {
    .prf = sa->prf,
    .key = skeyseed,
    .keylen = sizeof(skeyseed),
    .no_chunks = sizeof(sk_len),
    .data = second_msg,
    .datalen = sizeof(second_msg),
    .chunks = sk_ptr,
    .chunks_len = sk_len
  };

  /**
    * Execute prf+ (SKEYSEED, Ni | Nr | SPIi | SPIr )
    *
    * This will populate the IKE SA (the SK_* fields)
    */
  prf_plus(&prfplus_data);
}


/**
  * Get Child SA keying material as outlined in section 2.17
  *
  *     KEYMAT = prf+(SK_d, Ni | Nr)
  *
  * Encryption material from KEYMAT are used as follows:
   
      o All keys for SAs carrying data from the initiator to the responder are taken before SAs going from the responder to the initiator.
      
      o If multiple IPsec protocols are negotiated, keying material for each Child SA is taken in the order in which the protocol headers 
        will appear in the encapsulated packet.
        
      o If an IPsec protocol requires multiple keys, the order in which they are taken from the SA’s keying material needs to be described
        in the protocol’s specification. For ESP and AH, [IPSECARCH] defines the order, namely: the encryption key (if any) MUST be taken 
        from the first bits and the integrity key (if any) MUST be taken from the remaining bits.
  *
  * \parameter session The IKE session
  * \parameter incoming Incoming child SA
  * \parameter outgoing Outgoing child SA
  */
void ike_statem_get_child_keymat(ike_statem_session_t *session, sa_child_t *incoming, sa_child_t *outgoing)
{
  sa_child_t *i_to_r, *r_to_i;
  if (IKE_STATEM_IS_INITIATOR(session)) {
    i_to_r = outgoing;
    r_to_i = incoming;
  }
  else {
    r_to_i = outgoing;
    i_to_r = incoming;
  }
  
  uint8_t *keymat_ptr[] = { i_to_r->sk_e,                     i_to_r->sk_a,                                     r_to_i->sk_e,                     r_to_i->sk_a };
  uint8_t keymat_len[]  = { SA_ENCR_KEYMATLEN_BY_SA(*i_to_r), SA_INTEG_KEYMATLEN_BY_TYPE(i_to_r->integ), SA_ENCR_KEYMATLEN_BY_SA(*r_to_i), SA_INTEG_KEYMATLEN_BY_TYPE(r_to_i->integ) };

  // Compose message (Ni | Nr)
  uint8_t msg[IKE_PAYLOAD_MYNONCE_LEN + session->ephemeral_info->peernonce_len];
  uint8_t *my_nonce, *peer_nonce;
  if (IKE_STATEM_IS_INITIATOR(session)) {
    my_nonce = msg;
    peer_nonce = msg + IKE_PAYLOAD_MYNONCE_LEN; 
  }
  else {
    peer_nonce = msg;
    my_nonce = msg + session->ephemeral_info->peernonce_len; 
  }
  random_ike(my_nonce, IKE_PAYLOAD_MYNONCE_LEN, session->ephemeral_info->my_nonce_seed);      
  memcpy(peer_nonce, session->ephemeral_info->peernonce, session->ephemeral_info->peernonce_len);
    
  prfplus_data_t prfplus_data = {
    .prf = session->sa.prf,
    .key = session->sa.sk_d,
    .keylen = sizeof(session->sa.sk_d),
    .no_chunks = sizeof(keymat_len),
    .data = msg,
    .datalen = sizeof(msg),
    .chunks = keymat_ptr,
    .chunks_len = keymat_len
  };
  prf_plus(&prfplus_data);
}


/**
  * Traffic selector management
  */
  
/**
  * Copies a traffic selector pair into an ipsec_addr_set_t. Keep in mind that the IP address pointers of the address set must point to free memory.
  */
void ts_pair_to_addr_set(ipsec_addr_set_t *traffic_desc, ike_ts_t *ts_me, ike_ts_t *ts_peer)
{
  // peer_addr_from and peer_addr_to should point to the same memory location
  memcpy(traffic_desc->peer_addr_from, &ts_peer->start_addr, sizeof(uip_ip6addr_t));

  traffic_desc->nextlayer_proto = ts_me->proto;
  traffic_desc->my_port_from = uip_ntohs(ts_me->start_port);
  traffic_desc->my_port_to = uip_ntohs(ts_me->end_port);
  traffic_desc->peer_port_from = uip_ntohs(ts_peer->start_port);
  traffic_desc->peer_port_to = uip_ntohs(ts_peer->end_port);
}


/**
  * Instanciate an SPD entry to a traffic selector pair in accordance with RFC 4301. PFP flags are hardwired in this function, as elsewhere.
  */
void instanciate_spd_entry(const ipsec_addr_set_t *selector, uip_ip6addr_t *peer, ike_ts_t *ts_me, ike_ts_t *ts_peer)
{
  /**
    * Set common stuff
    */
  ts_peer->ts_type = ts_me->ts_type = IKE_PAYLOADFIELD_TS_TYPE;
  ts_peer->proto = ts_me->proto = selector->nextlayer_proto;
  ts_peer->selector_len = ts_me->selector_len = IKE_PAYLOADFIELD_TS_SELECTOR_LEN;

  /**
    * Address and port numbers
    */
  memcpy(&ts_peer->start_addr, peer, sizeof(uip_ip6addr_t));
  memcpy(&ts_peer->end_addr, peer, sizeof(uip_ip6addr_t));
  memcpy(&ts_me->start_addr, my_ip_addr, sizeof(uip_ip6addr_t));
  memcpy(&ts_me->end_addr, my_ip_addr, sizeof(uip_ip6addr_t));
  ts_peer->start_port = uip_htons(selector->peer_port_from);
  ts_peer->end_port = uip_htons(selector->peer_port_to);
  ts_me->start_port = uip_htons(selector->my_port_from);
  ts_me->end_port = uip_htons(selector->my_port_to);

  return;
}

/**
  * Traverse the SPD table from the top to the bottom and return the first protected entry that
  * is a subset of the traffic selector pair constituted by ts_me and ts_peer
  *
  * \return the entry that matched. NULL is returned if no such is found
  */
spd_entry_t *spd_get_entry_by_tspair(ike_ts_t *ts_me, ike_ts_t *ts_peer)
{
  uint8_t n;
  for (n = 0; n < SPD_ENTRIES; ++n) {
    PRINTSPDENTRY(&spd_table[n]);    
    if (selector_is_superset_of_tspair(&spd_table[n].selector, ts_me, ts_peer)) {
      PRINTF("This SPD entry is a superset of the TS pair\n");
      return &spd_table[n];
    }
  }
  return NULL;
}



/**
  * Is an SPD selector a superset of a TS pair?
  *
  * \return non-zero if selector is a superset of the TS pair, 0 otherwise
  */
uint8_t selector_is_superset_of_tspair(const ipsec_addr_set_t *selector, ike_ts_t *ts_me, ike_ts_t *ts_peer)
{
  // PRINTF("superset_of_tspair. SELECTOR:\n");
  // PRINTADDRSET(selector);
  // 
  // PRINTF("TS Pair:\n");
  // PRINTTSPAIR(ts_me, ts_peer);
  // Assert peer address range
  if (! (uip6_addr_a_is_in_closed_interval_bc(&ts_me->start_addr, selector->peer_addr_from, selector->peer_addr_to) &&
      uip6_addr_a_is_in_closed_interval_bc(&ts_me->end_addr, selector->peer_addr_from, selector->peer_addr_to)))
    return 0;
  PRINTF("addr ok\n");

  // Source port range
  if (! (a_is_in_closed_interval_bc(uip_ntohs(ts_me->start_port), selector->my_port_from, selector->my_port_to) &&
        a_is_in_closed_interval_bc(uip_ntohs(ts_me->end_port), selector->my_port_from, selector->my_port_to) &&
        a_is_in_closed_interval_bc(uip_ntohs(ts_peer->start_port), selector->peer_port_from, selector->peer_port_to) &&
        a_is_in_closed_interval_bc(uip_ntohs(ts_peer->end_port), selector->peer_port_from, selector->peer_port_to)
        ))
    return 0;
  PRINTF("port ok nl: ts_me->proto %u  selector->nextlayer_proto %u\n", ts_me->proto,  selector->nextlayer_proto);
  
  // Protocol (this assumes that ts_mee and ts_peer use the same proto, which they should)
  if (ts_me->proto != selector->nextlayer_proto &&
      ts_me->proto != IKE_PAYLOADFIELD_TS_NL_ANY_PROTOCOL &&
      selector->nextlayer_proto != SPD_SELECTOR_NL_ANY_PROTOCOL)
    return 0;
  PRINTF("nl ok\n");
  
  // Type (should be IPv6)
  return ts_me->ts_type == IKE_PAYLOADFIELD_TS_TYPE;
}

/** @} */
