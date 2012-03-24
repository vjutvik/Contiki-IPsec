/**
  * Pertains to Contiki's implementation of RFC 5996 (IKEv2)
  */

#include <lib/random.h>
//#include "machine.h"
#include "contikiecc/ecc/ecc.h"
#include "contikiecc/ecc/ecdh.h"
#include "transforms/integ.h"
#include "transforms/encr.h"
//#include "payload.h"
#include "common_ike.h"

/**
  * State machine for servicing an established session
  */
/*
void ike_statem_state_common_createchildsa(session, addr_t triggering_pkt, spd_entry_t commanding_entry)
{
  
}
*/

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
  notifyhdr->notify_msg_type = type;
  payload_arg->start += sizeof(ike_payload_notify_t);
  if (spi != 0) {
    notifyhdr->spi_size = 4;
    *payload_arg->start = spi;
    *payload_arg->start += 4;
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
  * Writes the initial TSi and TSr payloads
  */
/*
void ike_statem_write_tsitsr(payload_arg_t *payload_arg)
{
  ipsec_addr_set_t *spd_selector = &payload_arg->session->ephemeral_info->spd_entry->selector;
  ipsec_addr_t *trigger_addr = &payload_arg->session->ephemeral_info->triggering_pkt;
    
  
    * Initiator's traffic selectors (i.e. describing the source of the traffic)
    *
    * In blatant violation of the RFC the PFP flags are hardcoded. PFP is only used on
    * the address selector, other parameters are fetched from the matching SPD entry.
  
  //
  // PFP is hardcoded. PFP(SRCADDR) PFP(DSTADDR), other parameters are taken from SPD entry

  uint8_t *ptr = payload_arg->start;

  // TSi payload
  ike_payload_generic_hdr_t *tsi_genpayloadhdr;
  uint16_t tsir_size = sizeof(tsi_genpayloadhdr) + 2 * sizeof(ike_ts_t);
  SET_GENPAYLOADHDR(tsi_genpayloadhdr, payload_arg, IKE_PAYLOAD_TSi);
  tsi_genpayloadhdr->len = uip_htons(tsir_size);
  ike_ts_payload_t *tsi_payload = (ike_ts_payload_t *) payload_arg->start;
  SET_TSPAYLOAD(tsi_payload, 2);
  ptr += sizeof(tsi_payload);
  
  // Initiator's first traffic selector (triggering packet's params)
  ike_ts_t *tsi1 = (ike_ts_t *) ptr;
  ptr += sizeof(ike_ts_t);
  SET_TSSELECTOR_INIT(tsi1);
  SET_TSSAMEADDR(tsi1, trigger_addr->srcaddr);
  tsi1->proto = trigger_addr->nextlayer_type;
  tsi1->start_port = uip_htons(addr->srcport);
  tsi1->end_port = uip_htons(addr->srcport);
  
  // Initiator's second traffic selector (instanciation of the matching SPD entry)
  ike_ts_t *tsi2 = (ike_ts_t *) ptr;
  ptr += sizeof(ike_ts_t);
  SET_TSSELECTOR_INIT(tsi2);
  SET_TSSAMEADDR(tsi2, trigger_addr->srcaddr); // PFP (triggering pkt)
  tsi2->proto = spd_selector->nextlayer_type; // Not PFP (SPD entry)
  tsi2->start_port = uip_htons(spd_selector->nextlayer_src_port_range_from); // Not PFP (SPD entry)
  tsi2->end_port = uip_htons(spd_selector->nextlayer_src_port_range_to); // Not PFP (SPD entry)


  // TSr payload
  ike_payload_generic_hdr_t *tsr_genpayloadhdr = (ike_payload_generic_hdr_t *) ptr;
  SET_GENPAYLOADHDR(tsr_genpayloadhdr, IKE_PAYLOAD_TSr);
  tsr_genpayloadhdr->len = tsir_size;
  ptr += sizeof(tsr_genpayloadhdr);
  ike_ts_payload_t *tsr_payload = (ike_ts_payload_t *) ptr;  
  SET_TSPAYLOAD(tsr_payload, 2);
  ptr += sizeof(tsr_payload);

  // Responder's first traffic selector
  ike_ts_t *tsr1 = (ike_ts_t *) ptr;
  ptr += sizeof(ike_ts_t);
  SET_TSSELECTOR_INIT(tsr1);
  tsr1->proto = addr->nextlayer_type;
  tsr1->start_port = addr->dstport;
  tsr1->end_port = addr->dstport;
  memcpy(&tsr1->start_addr, addr->srcaddr, sizeof(addr->srcaddr));
  memcpy(&tsr1->end_addr, addr->srcaddr, sizeof(addr->srcaddr));

  // Responder's second traffic selector
  ike_ts_t *tsr2 = (ike_ts_t *) ptr;
  ptr += sizeof(ike_ts_t);
  SET_TSSELECTOR_INIT(tsr2);
  SET_TSSAMEADDR(tsr2, trigger_addr->dstaddr); // PFP (triggering pkt)
  tsr2->proto = spd_selector->nextlayer_type; // Not PFP (SPD entry)
  tsr2->start_port = uip_htons(spd_selector->nextlayer_dst_port_range_from); // Not PFP (SPD entry)
  tsr2->end_port = uip_htons(spd_selector->nextlayer_dst_port_range_to); // Not PFP (SPD entry)
  
  payload_arg->start = ptr;
}
*/


/**
  * Take the offer and write the corresponding SA payload to memory starting at payload_arg->start.
  * Handles IKE SA- as well as Child SA-offers.
  *
  * \parameter payload_arg Payload argument
  * \parameter offer The offer chain. Probably one from spd_conf.c.
  * \parameter spi The SPI of offer's proposals (We only support one SPI per offer. Nothing tells us that this is illegal.)
  */
void ike_statem_write_sa_payload(payload_arg_t *payload_arg, spd_proposal_tuple_t *offer, uint32_t spi)
{
  // Write the SA payload
  ike_payload_generic_hdr_t *sa_genpayloadhdr = (ike_payload_generic_hdr_t *) payload_arg->start;
  SET_GENPAYLOADHDR(sa_genpayloadhdr, payload_arg, IKE_PAYLOAD_SA);
  
  // Loop over the offers associated with this policy
  uint8_t *ptr = payload_arg->start;
  uint8_t numtransforms = 0;
  
  ike_payload_transform_t *transform = NULL;
  ike_payload_proposal_t *proposal = NULL;
  u8_t n = 0;
  uint8_t proposal_number = 1;
  do {  // Loop over the offer's tuples
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
      proposal->clear = IKE_MSG_ZERO;

      proposal->proposal_number = proposal_number;
      proposal->proto_id = offer[n].value;

      numtransforms = 0;

      ++proposal_number;
      ptr += sizeof(ike_payload_proposal_t);
      
      // There are some differences between the IKE protocol and the other ones
      if (proposal->proto_id == SA_PROTO_IKE) {
        if (spi) {
          proposal->spi_size = 8;
          *((uint32_t *) ptr) = IKE_MSG_ZERO;
          *((uint32_t *) ptr + 4) = spi;
          ptr += 8;
        }
        else {
          // This case will occur whenever we negotiate the first IKE
          // p.79: "For an initial IKE SA negotiation, this field MUST be zero"
          proposal->spi_size = IKE_MSG_ZERO;
        }
      }
      else { // AH and ESP
        proposal->spi_size = 4;
        *((uint32_t *) ptr) = spi;
        ptr += 4;
        
        // We don't support ESNs. Start our offer with a plain no.
        transform = (ike_payload_transform_t *) ptr;
        transform->last_more = IKE_PAYLOADFIELD_TRANSFORM_MORE;
        transform->type = SA_CTRL_TRANSFORM_TYPE_ESN;
        transform->clear1 = transform->clear2 = IKE_MSG_ZERO;
        transform->len = uip_htons(sizeof(ike_payload_transform_t));
        transform->id = uip_htons(SA_ESN_NO);
        ptr += sizeof(ike_payload_transform_t);
      }
      break;
      
      case SA_CTRL_TRANSFORM_TYPE_ENCR:   // Encryption Algorithm (ESP, IKE)      
      case SA_CTRL_TRANSFORM_TYPE_PRF:    // Pseudorandom function (IKE)
      case SA_CTRL_TRANSFORM_TYPE_INTEG:  // Integrity Algorithm (IKE, AH, ESP (optional))
      case SA_CTRL_TRANSFORM_TYPE_DH:     // Diffie-Hellman group (IKE, AH (optional), ESP (optional))
      transform = (ike_payload_transform_t *) ptr;
      transform->last_more = IKE_PAYLOADFIELD_TRANSFORM_MORE;
      transform->type = offer[n].type;
      transform->clear1 = transform->clear2 = IKE_MSG_ZERO;
      transform->id = uip_htons(offer[n].value);
      ptr += sizeof(ike_payload_transform_t);

      // Loop over any attributes associated with this transform
      // Value type: Key length of encryption algorithm
      u8_t j = n + 1;
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
      PRINTF(IPSEC_IKE ": ike_statem_write_sa_payload: Error: Unexpected SA_CTRL\n");
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
  
int8_t ike_statem_parse_sa_payload(spd_proposal_tuple_t *my_offer, 
                                ike_payload_generic_hdr_t *sa_payload_hdr, 
                                uint8_t ke_dh_group,
                                sa_ike_t *ike_sa,
                                sa_child_t *child_sa,
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
  ike_payload_proposal_t *peerproposal = (ike_payload_proposal_t *) (((uint8_t *) sa_payload_hdr) + sizeof(ike_payload_generic_hdr_t));
  PRINTF("sa_payload_hdr: %p, peerproposal: %p\n", sa_payload_hdr, peerproposal);
  
  // (#1) Loop over the proposals in the peer's offer
  while((uint8_t *) peerproposal < ((uint8_t *) sa_payload_hdr) + uip_ntohs(sa_payload_hdr->len)) {
    PRINTF(IPSEC_IKE "#1 Looking at peerproposal %p\n", peerproposal);

    // Assert proposal properties
    if (ike && (peerproposal->proto_id != SA_PROTO_IKE || peerproposal->spi_size != 0)) {
      PRINTF(IPSEC_IKE "#1 Rejecting non-IKE proposal\n");
      goto next_peerproposal;
    }
    if (!ike && (peerproposal->proto_id != SA_PROTO_ESP || peerproposal->spi_size != 4)) {
      PRINTF(IPSEC_IKE "#1 Rejecting non-ESP proposal\n");
      goto next_peerproposal;
    }
    
    spd_proposal_tuple_t *mytuple = my_offer;
    accepted_transform_subset[0].type = SA_CTRL_NEW_PROPOSAL;
    if (ike)
      accepted_transform_subset[0].value = SA_PROTO_IKE;
    else
      accepted_transform_subset[0].value = SA_PROTO_ESP;
    
    // (#2) Loop over my proposals and see if any of them is a superset of this peer's current proposal
    while (mytuple->type != SA_CTRL_END_OF_OFFER) {
      // We're now at the beginning of one of our offers.
      PRINTF("#2 At the beginning of one our offers\n");
            
      ++mytuple; // Jump the SA_CTRL_NEW_PROPOSAL
      memset(candidates, 0, sizeof(candidates));
      uint8_t accepted_transforms = 0;  // Number of accepted transforms
      
      // (#3) Loop over this proposal in my offer
      while (mytuple->type != SA_CTRL_END_OF_OFFER && mytuple->type != SA_CTRL_NEW_PROPOSAL) {        
        // Does this transform have an attribute?

        PRINTF(IPSEC_IKE "\n#3 Looking at mytuple->type %u mytuple->value %u\n", mytuple->type, mytuple->value);
        u8_t my_keylen = 0;
        acc_proposal_ctr = 1;
        if ((mytuple + 1)->type == SA_CTRL_ATTRIBUTE_KEY_LEN)
          my_keylen = (mytuple + 1)->type;
        
        ike_payload_transform_t *peertransform = (ike_payload_transform_t *) ((uint8_t *) peerproposal + sizeof(ike_payload_proposal_t) + peerproposal->spi_size);
        
        // (#4) Loop over the peer's proposal and see if this transform of mine can be found
        while((uint8_t *) peertransform < (uint8_t *) peerproposal + uip_ntohs(peerproposal->proposal_len)) {
//          PRINTF(IPSEC_IKE "#4 peertransform->type %u. mytuple->type (%u), peertransform->id: %u. mytuple->value: %u \n", peertransform->type, mytuple->type, uip_ntohs(peertransform->id), mytuple->type);
          PRINTF(IPSEC_IKE "#4 peertransform->type %u, peertransform->id: %u\n", peertransform->type, uip_ntohs(peertransform->id));

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
                  candidate_keylen = uip_ntohs(peer_attrib->attribute_value);
                }
              }
              else
                goto next_peertransform;                
            }
            // We end up here if we've accepted the transform
            PRINTF(IPSEC_IKE "#4 Is candidate\n");              
            
            // Add the transform to the resulting output offer
            ++acc_proposal_ctr;
            memcpy(&accepted_transform_subset[++acc_proposal_ctr], mytuple, sizeof(spd_proposal_tuple_t));
            if (candidate_keylen) {
              accepted_transform_subset[++acc_proposal_ctr].type = SA_CTRL_ATTRIBUTE_KEY_LEN;
              accepted_transform_subset[acc_proposal_ctr].value = candidate_keylen;
            }
            PRINTF(IPSEC_IKE "#4 acc_proposal_ctr (output offer pointer) increased: %u\n", acc_proposal_ctr);
            
            // Set the SA
            candidates[mytuple->type] = mytuple->value;
            ++accepted_transforms;
            PRINTF(IPSEC_IKE "#4 Accepted transforms is now %u\n", accepted_transforms);
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
    ike_sa->integ = candidates[SA_CTRL_TRANSFORM_TYPE_INTEG];
    ike_sa->prf = candidates[SA_CTRL_TRANSFORM_TYPE_PRF];
    ike_sa->dh = candidates[SA_CTRL_TRANSFORM_TYPE_DH];
  }
  else {
    child_sa->encr = candidates[SA_CTRL_TRANSFORM_TYPE_ENCR];
    child_sa->integ = candidates[SA_CTRL_TRANSFORM_TYPE_INTEG];
  }
  
  return 0; // Success
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
  ike_payload_generic_hdr_t *sk_genpayloadhdr = (ike_payload_generic_hdr_t *) payload_arg->start;
  SET_GENPAYLOADHDR(sk_genpayloadhdr, payload_arg, IKE_PAYLOAD_SK);

  // Generate the IV
  uint8_t n;
  for (n = 0; n < SA_ENCR_CURRENT_IVLEN(payload_arg->session); n += 2)
    payload_arg->start[n] = random_rand();

  sk_genpayloadhdr->len = uip_htons(payload_arg->start - (uint8_t *) sk_genpayloadhdr);
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
  * \parameter len The length of the payloads to be encrypted
  */
/*
void ike_statem_finalize_sk(ike_statem_session_t *session, ike_payload_generic_hdr_t *sk_genpayloadhdr, uint16_t len)
{
  // Encrypt
  encr_data_t encr_data = {
    .type = session->sa.encr,                              // This determines transform and block size among other things
    .encr_data = (uint8_t *) sk_genpayloadhdr + sizeof(sk_genpayloadhdr),   // Address of IV. The actual data is expected to follow one block size after.
    .encr_datalen = len,                                         // Length of the data (not including the IV)
    .keymat = 
    .keylen = session->sa.encr_keylen                      // Length of the key _in bytes_
  };
  IKE_STATEM_IS_INITIATOR(session) ? 
          encr_data.keymat = session->sa.sk_ei :
          encr_data.keymat = session->sa.sk_er;                // Address of the keying material

  uint8_t *integ_chksum = encr(&encr_data);                      // This will write Encrypted Payloads, padding and pad length
  
  // Write Integrity Checksum Data
  uint8_t integ_len = SA_INTEG_CURRENT_KEYMATLEN(session);
  prf_data_t prf_data = {
    .out = &integ_chksum,
    .outlen = integ_len,
    .key = (IKE_STATEM_IS_INITIATOR(session) ? 
              &session->sa.sk_ai :
              &session->sa.sk_ar ),
    .keylen = integ_len,
    .data = &udp_buf,
    .datalen = integ_chksum - udp_buf;
  };
  integ(payload_arg->session->sa.integ, &data);
}
*/


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
  * Performs the calculations as described in section 2.14
  *
    SKEYSEED = prf(Ni | Nr, g^ir)

    {SK_d | SK_ai | SK_ar | SK_ei | SK_er | SK_pi | SK_pr }
                    = prf+ (SKEYSEED, Ni | Nr | SPIi | SPIr )
  *
  * \parameter session The session concerned
  * \parameter peer_pub_key Address of the beginning of the field "Key Exchange Data" in the peer's KE payload
  * \return The address that follows the last byte of the nonce
  */
void ike_statem_get_keymat(ike_statem_session_t *session, uint8_t *peer_pub_key)
{
  // Calculate the DH exponential: g^ir
  PRINTF(IPSEC_IKE "Calculating shared secret\n");
  uint8_t gir[IKE_DH_GIR_LEN];
  ecdh_get_shared_secret(gir, ECDH_DESERIALIZE_TO_POINTT(peer_pub_key), ECDH_DESERIALIZE_TO_NN(session->ephemeral_info->my_prv_key));
  PRINTF("done\n");
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
  uint8_t skeyseed[SA_PRF_OUTPUT_LEN(session)];
  random_ike(mynonce_start, IKE_PAYLOAD_MYNONCE_LEN, &session->ephemeral_info->my_nonce_seed);
  memcpy(peernonce_start, session->ephemeral_info->peernonce, session->ephemeral_info->peernonce_len);

  prf_data_t prf_data =
    {
      .out = skeyseed,
      .key = first_key,
      .keylen = first_keylen,
      .data = gir,
      .datalen = IKE_DH_GIR_LEN
    };
  prf(session->sa.prf, &prf_data);


  /**
    * Complete the next step:
    * 
      {SK_d | SK_ai | SK_ar | SK_ei | SK_er | SK_pi | SK_pr }
                  = prf+ (SKEYSEED, Ni | Nr | SPIi | SPIr )
    */

  /**
    * Compile the second message (Ni | Nr | SPIi | SPIr)
    */
  random_ike(ni_start, IKE_PAYLOAD_MYNONCE_LEN, &session->ephemeral_info->my_nonce_seed);      
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
  uint8_t *sk_ptr[] = { sa->sk_d,                             sa->sk_ai,                        sa->sk_ar,                            sa->sk_ei,                      sa->sk_er,                        session->ephemeral_info->sk_pi,       session->ephemeral_info->sk_pr};
  uint8_t sk_len[]  = { SA_PRF_PREFERRED_KEYMATLEN(session), SA_INTEG_CURRENT_KEYMATLEN(session), SA_INTEG_CURRENT_KEYMATLEN(session), SA_ENCR_CURRENT_KEYLEN(session), SA_ENCR_CURRENT_KEYLEN(session), SA_PRF_PREFERRED_KEYMATLEN(session), SA_PRF_PREFERRED_KEYMATLEN(session)};
  
  prfplus_data_t prfplus_data = {
    .prf = sa->prf,
    .key = skeyseed,
    .keylen = sizeof(skeyseed),
    .no_chunks = 7,
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


/* Don't use it. */
/*
uint8_t ike_statem_write_rnd_data(uint16_t *ptr, uint16_t no_16bit_chunks)
{
  for (int n = 0; n < no_16bit_chunks; ++no_16bit_chunks)
    ptr[no_16bit_chunks] = rnd16();
  
  return ptr - 1;
}
*/
