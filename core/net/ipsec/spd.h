/**
 * \addtogroup ipsec
 * @{
 */

/**
 * \file
 * 					The SPD's interface
 * \details
 * 					Headers for the implementation of the Security Policy Database (SPD).
 * 					
 * 					All values and definitions described herein pertains to RFC 4301 (Security Architecture for IP)
 * 					unless otherwise stated.
 * 					
 * 					This implementation of the SPD only covers a subset of the features described in the RFC. The general
 * 					limitations are: only support for IPv6; no tunnel mode (hence no fragmentation support). 
 * 					
 * 					Limitations of lesser importance and design decisions are noted, and their rationale explained in the
 * 					code below. 
 *
 * \author
 *					Vilhelm Jutvik <ville@imorgon.se>
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
 
#ifndef __SPD_H__
#define __SPD_H__

#include "common_ipsec.h"
#include "sa.h"
#include "net/uip.h"

// The number of entries in spd_table. Adjust according to need.
#define SPD_ENTRIES 6


/**
  * Debug stuff
  */
#ifdef DEBUG
// Prints the SPD entry located at address spd_entry
#define PRINTSPDENTRY(spd_entry)                              \
  do {                                                        \
    PRINTF("Selector: ");                                     \
    /* PRINTADDRSET(&(spd_entry)->selector);   */                  \
    uint8_t str[3][8] = {                                     \
      { "PROTECT" },                                          \
      { "BYPASS" },                                           \
      { "DISCARD" }                                           \
    };                                                        \
    PRINTF("Action: %s\n", str[(spd_entry)->proc_action]);    \
    PRINTF("Offer at addr: %p\n", (spd_entry)->offer);        \
  } while(0)

#define PRINTSPDLOOKUPADDR(addr)																		\
	do {																												\
		PRINTF("SPD lookup for traffic:\n");											\
		PRINTADDR(addr);																					\
	} while(0)

#define PRINTFOUNDSPDENTRY(spd_entry)                          \
	do {                                                         \
  	PRINTF("Found SPD entry:\n");                              \
  	PRINTSPDENTRY(spd_entry);                                  \
	} while(0)                                                   \

#else
#define PRINTFOUNDSPDENTRY
#define SDPLOOKUPADDR
#define PRINTSPDENTRY
#endif


/**
  * This enum represents the values of the policy process actions as described
  * in section 3.
  *
  * \hideinitializer
  */
typedef enum {
  SPD_ACTION_PROTECT,
  SPD_ACTION_BYPASS,
  SPD_ACTION_DISCARD
} spd_proc_action_t;


/**
  * The process action PROTECT (as described above) are associated with the following details as
  * described in section 4.4.1.2.
  *
  * As of now, the following features / specifications are omitted in violation of the RFC:
  *   Tunnel or transport (the implementation only supports transport as of now)
  *   Extended sequence number (not supported by the implementation)
  *   Stateful fragment checking (not supported by the implementation)
  *   Algorithms for combined SA's (combinations of ESP and AH SAs are not supported by the implementation)
  *
  * \hideinitializer
  */


/**
  *
  * Datastructure for encoding SA offers
  *
  * The structure below is used for encoding the SA proposals as described in section 3.3 in RFC 5996.
  * As you see, the tuples consists of a \b type and a \b value. The former describes the type of later, for example;
  *   <SA_TRANSFORM_TYPE_ENCR, SA_ENCR_AES_CBC> (that is, encryption algorithm is of type SA_ENCR_AES_CBC)
  * One now realises that theses tuples can be used to represent the tree structure of an SA offer (see p. 76). The proposals
  * are ordered by preference in descending order.
  *
  * Writing a proper grammar for the "offer tree" is tedious, but below you'll find a set of rules that express
  * almost the same. There should also be examples to look at in spd_conf.c.
  *
  * ===Tail token===                                          ===Token(s) that can be appended===
  *
  * EMPTY ARRAY                                         ->    <SA_CTRL_NEW_PROPOSAL, any sa_ipsec_proto_type_t>
  * <SA_CTRL_NEW_PROPOSAL, any sa_ipsec_proto_type_t>   ->    <SA_CTRL_TRANSFORM_*, anything applicable to the given type>
  * <SA_CTRL_TRANSFORM_TYPE_ENCR, *>                    ->    <SA_CTRL_ATTRIBUTE_KEY_LEN, *>
  * <SA_CTRL_END_OF_OFFER, *>                           ->    END OF ARRAY
  * < not SA_CTRL_NEW_PROPOSAL, *>                      ->    <SA_CTRL_NEW_PROPOSAL, any sa_ipsec_proto_type_t>
  * < *, *>                                             ->    <SA_CTRL_END_OF_OFFER, *> 
  *                   (parse above rule set top-down as some set selectors overlap)
  *
  * Now, despite manuals, we all make mistakes. Therefore I've elected to list a few common ones so that you can avoid them:
  *   -> SA_CTRL_NEW_PROPOSAL must be followed by one or more transforms.
  *   -> The array must always end with SA_CTRL_END_OF_OFFER.
  *   -> The proposals should be ordered in 
  *
  * An array of such tuples ordered with respect to the above invariants will form a parseable proposal. Please
  * note that there are more constraints which need to be taken into consideration in order to craft a valid set of
  * SA proposals. For example; it doesn't make sense to include an encryption transform in an AH-proposal. Therefore 
  * it's recommended that you read section 3.3 before crafting your own proposals.
  *
  * The struct is two bytes large and the compiler won't insert any padding.
  *
  */
typedef struct {
	sa_ctrl_t type;
  uint8_t value;
} spd_proposal_tuple_t;



/**
  * The following struct represents the policy entry as described in RFC 4301, sections 4.4.1.1-2.
  * Traffic (packets) matching an entry's set of packets (expressed by \c selector) are targeted for the
  * process action \c proc_action.
  *
  * Shortcomings in respect to the RFC:
  *  The name selector is not implemented
  *  The symbolic OPAQUE identifier is not an implemented selector value as the choice to not implement
  *   support for packet fragmentation makes it unnecessary.
  *  The traffic selector is not as expressive as defined in the standard, but sufficient for Contiki.
  *  
  * Syntax conventions for symbolic selector values as mentioned in the standard: 
  *   ANY -selectors are represented as ranges [0, maximum value]
  *   (OPAQUE is not implemented since its only applies to fragmented packets. Fragmentation doesn't occur since we
  *   don't implement tunnel mode.)
  *
  */
typedef const struct {
  ipsec_addr_set_t selector;        // The selector identifying targeted traffic
  spd_proc_action_t proc_action;    // The process action for the traffic

  // If the process action of this entry is SPD_ACTION_PROTECT the IKE subsystem will be invoked to perform
  // a cryptoograhic handshake with the remote host. The address below points to an array of configuration
  // proposals to be offered to the remote host. This value is ignored for other process actions.
  const spd_proposal_tuple_t *offer;
  
  //spd_action_protect_details_t *action_protect_details;
} spd_entry_t;



/**
  * ( \return An in-order subset of the SPD whose member have the property that their selectors
  * constitute a subset of the \c selectors. )
  *
  * \param selector The packet's header
  *
  * \return the security policy entry that applies to the pattern formed by \c pkt_hdr
  *
  */
spd_entry_t *spd_get_entry(ipsec_addr_t *);
spd_entry_t *spd_get_entry_by_addr(ipsec_addr_t *addr);
void spd_conf_init(void);


#endif

/** @} */

