/**
 * \addtogroup ipsec
 * @{
 */

/**
 * \file
 * 		Definitions for the IKEv2 payloads
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

#ifndef __PAYLOAD_H__
#define __PAYLOAD_H__

/**
  * Data structures describing IKE payloads and headers as found in RFC 5996.
  * 
  * Please note that these structures (fields as well as their data) will be read and written
  * directly to and from the network interface. Therefore memory alignment, endianness and other
  * binary considerations must be taken into account. Thus, you must uphold the following constraints:
  *
  * -> All data structures must begin at 32 bit word limits (be carefull when casting your pointers).
  * -> Numbers must be expressed in network byte order (or the other peer won't understand you)
  */

#include "ike/prf.h"
#include "uip.h"

/**
  * Payload types as described on p. 74 *
  */
typedef enum {
  IKE_PAYLOAD_NO_NEXT = 0,
  IKE_PAYLOAD_SA = 33,  // Security Association        
  IKE_PAYLOAD_KE,       // Key Exchange                
  IKE_PAYLOAD_IDi,      // Identification - Initiator   
  IKE_PAYLOAD_IDr,      // Identification - Responder  
  IKE_PAYLOAD_CERT,     // Certificate                 
  IKE_PAYLOAD_CERTREQ,  // Certificate Request         
  IKE_PAYLOAD_AUTH,     // Authentication              
  IKE_PAYLOAD_NiNr,     // Nonce (initiator or responder)
  IKE_PAYLOAD_N,        // Notify                      
  IKE_PAYLOAD_D,        // Delete                      
  IKE_PAYLOAD_V,        // Vendor ID                   
  IKE_PAYLOAD_TSi,      // Traffic Selector - Initiator
  IKE_PAYLOAD_TSr,      // Traffic Selector - Responder
  IKE_PAYLOAD_SK,       // Encrypted and Authenticated 
  IKE_PAYLOAD_CP,       // Configuration               
  IKE_PAYLOAD_EAP       // Extensible Authentication   
} ike_payload_type_t;                            



/**
  * The IKEv2 header (p. 70)
  *
                         1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                       IKE SA Initiator's SPI                  |
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                       IKE SA Responder's SPI                  |
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Next Payload | MjVer | MnVer | Exchange Type |     Flags     |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                          Message ID                           |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                            Length                             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                     Figure 4:  IKE Header Format
*/
#define IKE_PAYLOADFIELD_IKEHDR_VERSION_STRING 0x20 // concat(MjVer, MnVer) (Major 2, Minor 0)
#define IKE_PAYLOADFIELD_IKEHDR_FLAGS_INITIATOR 0x8
#define IKE_PAYLOADFIELD_IKEHDR_FLAGS_RESPONDER 0x2

#define IKE_PAYLOADFIELD_IKEHDR_FLAGS_REQUEST 0x0
#define IKE_PAYLOADFIELD_IKEHDR_FLAGS_RESPONSE 0x20

typedef enum {
  IKE_PAYLOADFIELD_IKEHDR_EXCHTYPE_SA_INIT = 34,
  IKE_PAYLOADFIELD_IKEHDR_EXCHTYPE_IKE_AUTH,
  IKE_PAYLOADFIELD_IKEHDR_EXCHTYPE_CREATE_CHILD_SA,
  IKE_PAYLOADFIELD_IKEHDR_EXCHTYPE_INFORMATIONAL
} ike_payloadfield_ikehdr_exchtype_t;

/**
  * Macros for setting the IKE header. Endian conversions are not performed as they are
  * for all practical purposes unnecessary.
  */
#define SET_IKE_HDR(payload_arg, exchtype, flags_arg, msg_id) \
  ((ike_payload_ike_hdr_t *) (payload_arg)->start)->version = IKE_PAYLOADFIELD_IKEHDR_VERSION_STRING;   \
  ((ike_payload_ike_hdr_t *) (payload_arg)->start)->exchange_type = exchtype;                           \
  ((ike_payload_ike_hdr_t *) (payload_arg)->start)->flags = flags_arg;                                  \
  ((ike_payload_ike_hdr_t *) (payload_arg)->start)->message_id = uip_htonl((uint32_t) msg_id);          \
  (payload_arg)->prior_next_payload = &((ike_payload_ike_hdr_t *) (payload_arg)->start)->next_payload;  \
  (payload_arg)->start += sizeof(ike_payload_ike_hdr_t)


#define SET_IKE_HDR_AS_RESPONDER(payload_arg, exchtype, response_or_request) \
  ((ike_payload_ike_hdr_t *) (payload_arg)->start)->sa_initiator_spi_high = (payload_arg)->session->peer_spi_high;  \
  ((ike_payload_ike_hdr_t *) (payload_arg)->start)->sa_initiator_spi_low = (payload_arg)->session->peer_spi_low;    \
  ((ike_payload_ike_hdr_t *) (payload_arg)->start)->sa_responder_spi_high = 0U;                           \
  ((ike_payload_ike_hdr_t *) (payload_arg)->start)->sa_responder_spi_low = uip_htonl((uint32_t) IKE_STATEM_MYSPI_GET_MYSPI((payload_arg)->session)); \
  SET_IKE_HDR((payload_arg), exchtype, IKE_PAYLOADFIELD_IKEHDR_FLAGS_RESPONDER | response_or_request, (payload_arg)->session->my_msg_id)

#define SET_IKE_HDR_AS_INITIATOR(payload_arg, exchtype, response_or_request) \
  ((ike_payload_ike_hdr_t *) (payload_arg)->start)->sa_responder_spi_high = (payload_arg)->session->peer_spi_high;  \
  ((ike_payload_ike_hdr_t *) (payload_arg)->start)->sa_responder_spi_low = (payload_arg)->session->peer_spi_low;    \
  ((ike_payload_ike_hdr_t *) (payload_arg)->start)->sa_initiator_spi_high = 0U;                           \
  ((ike_payload_ike_hdr_t *) (payload_arg)->start)->sa_initiator_spi_low = uip_htonl((uint32_t) IKE_STATEM_MYSPI_GET_MYSPI((payload_arg)->session)); \
  SET_IKE_HDR((payload_arg), exchtype, IKE_PAYLOADFIELD_IKEHDR_FLAGS_INITIATOR | response_or_request, (payload_arg)->session->my_msg_id)


typedef struct {
  // Please note that we treat the IKE SPIs as 4 byte values internally
  uint32_t sa_initiator_spi_high;
  uint32_t sa_initiator_spi_low;
  uint32_t sa_responder_spi_high;
  uint32_t sa_responder_spi_low;
  
  uint8_t next_payload;  /* ike_payload_type_t */
  uint8_t version;
  uint8_t exchange_type; /* ike_payloadfield_ikehdr_exchtype_t */
  uint8_t flags;
  
  uint32_t message_id;
  uint32_t len; // Length of header + payload
} ike_payload_ike_hdr_t;


/**
  * The generic payload header (p. 73)
  *
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    | Next Payload  |C|  RESERVED   |         Payload Length        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                     Figure 5:  Generic Payload Header
*/
/**
  * genpayloadhdr is of type *ike_payload_generic_hdr_t
  * payload_arg is of type *payload_arg_t
  * payload_id is of type ike_payload_type_t
  */
#define SET_GENPAYLOADHDR(genpayloadhdr, payload_arg, payload_id)                         \
                     genpayloadhdr = (ike_payload_generic_hdr_t *) (payload_arg)->start;  \
                     *(payload_arg)->prior_next_payload = payload_id;                     \
                     (payload_arg)->prior_next_payload = &genpayloadhdr->next_payload;    \
                     genpayloadhdr->clear = 0U;                                 \
                     (payload_arg)->start += sizeof(ike_payload_generic_hdr_t)

#define SET_NO_NEXT_PAYLOAD(payload_arg) \
                     *(payload_arg)->prior_next_payload = IKE_PAYLOAD_NO_NEXT
typedef struct {
  uint8_t next_payload;  /* ike_payload_type_t */
  uint8_t clear;
  uint16_t len; // Length of payload header + payload
} ike_payload_generic_hdr_t;


/**
  * The proposal substructure (p. 78)
  *
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    | 0 (last) or 2 |   RESERVED    |         Proposal Length       |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    | Proposal Num  |  Protocol ID  |    SPI Size   |Num  Transforms|
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ~                        SPI (variable)                         ~
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    ~                        <Transforms>                           ~
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    
          Figure 7:  Proposal Substructure
  */
#define IKE_PAYLOADFIELD_PROPOSAL_LAST 0
#define IKE_PAYLOADFIELD_PROPOSAL_MORE 2
typedef struct {
  uint8_t last_more;
  uint8_t clear;
  uint16_t proposal_len;
  
  uint8_t proposal_number;
  uint8_t proto_id;         /* sa_ipsec_proto_type_t */
  uint8_t spi_size;
  uint8_t numtransforms;
  
  // The SPI field is not included since it is omitted from this
  // payload in the case of IKE negotiation proposal.
} ike_payload_proposal_t;


/**
  * Transform substructure
  *
                     1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  | 0 (last) or 3 |   RESERVED    |        Transform Length       |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |Transform Type |   RESERVED    |          Transform ID         |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                                                               |
  ~                      Transform Attributes                     ~
  |                                                               |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

           Figure 8:  Transform Substructure
  */
#define IKE_PAYLOADFIELD_TRANSFORM_LAST 0
#define IKE_PAYLOADFIELD_TRANSFORM_MORE 3
typedef struct {
  uint8_t last_more;
  uint8_t clear1;
  uint16_t len;

  uint8_t type;
  uint8_t clear2;
  uint16_t id;
} ike_payload_transform_t;


/**
  * Transform attribute (p. 84)
  * The only attribute that the standard defines is that of key length. Therefore
  * AF is always set to 1 and the payload ends after 32 bits.
  *
                       1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |A|       Attribute Type        |    AF=0  Attribute Length     |
  |F|                             |    AF=1  Attribute Value      |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                   AF=0  Attribute Value                       |
  |                   AF=1  Not Transmitted                       |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                  Figure 9:  Data Attributes
  */
#define IKE_PAYLOADFIELD_ATTRIB_VAL (UIP_HTONS((uint16_t) 0x8000) | UIP_HTONS((uint16_t) SA_ATTRIBUTE_KEYLEN_ID))
typedef struct {
  uint16_t af_attribute_type; // The first bit should always be set
  uint16_t attribute_value;
} ike_payload_attribute_t;


/**
  * Key Exchange payload (p. 87)
  * The field key exchange data is not included the struct since it's of variable length.
  *
                       1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  | Next Payload  |C|  RESERVED   |         Payload Length        |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |   Diffie-Hellman Group Num    |           RESERVED            |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                                                               |
  ~                       Key Exchange Data                       ~
  |                                                               |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

            Figure 10:  Key Exchange Payload Format
  */
typedef struct {
  uint16_t dh_group_num;
  uint16_t clear;
} ike_payload_ke_t;


/**
  * Authentication payload (p. 95)
  *
                       1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  | Next Payload  |C|  RESERVED   |         Payload Length        |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  | Auth Method   |                RESERVED                       |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                                                               |
  ~                      Authentication Data                      ~
  |                                                               |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

             Figure 14:  Authentication Payload Format
  */
//#define SET_AUTHPAYLOAD(authpayload, auth_method) *((uint8_t *) authpayload = (uint32_t) auth_method << 24
typedef struct {
  uint8_t auth_type;  /* ike_auth_type_t */
  uint8_t clear1;
  uint16_t clear2;
} ike_payload_auth_t;


/**
  * Nonce payload (p. 96)

                       1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  | Next Payload  |C|  RESERVED   |         Payload Length        |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                                                               |
  ~                            Nonce Data                         ~
  |                                                               |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  
               Figure 15:  Nonce Payload Format
  *
  */
// See Section 2.10, p. 44 for a discussion of nonce data length.
// 16 B = 128 bits.
#define IKE_PAYLOAD_MYNONCE_LEN 16
#define IKE_PAYLOAD_PEERNONCE_LEN 32

/**
  * Notify payload (p. 97)
  
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  | Next Payload  |C|  RESERVED   |         Payload Length        |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |  Protocol ID  |   SPI Size    |      Notify Message Type      |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                                                               |
  ~                Security Parameter Index (SPI)                 ~
  |                                                               |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                                                               |
  ~                       Notification Data                       ~
  |                                                               |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

           Figure 16:  Notify Payload Format
  *
  */
typedef struct {
  uint8_t proto_id;   /* sa_ipsec_proto_type_t */
  uint8_t spi_size;
  uint16_t notify_msg_type; /* notify_msg_type_t */
} ike_payload_notify_t;

typedef enum {
  // Error types
  IKE_PAYLOAD_NOTIFY_UNSUPPORTED_CRITICAL_PAYLOAD = 1,
  IKE_PAYLOAD_NOTIFY_INVALID_IKE_SPI = 4,
  IKE_PAYLOAD_NOTIFY_INVALID_MAJOR_VERSION = 5,
  IKE_PAYLOAD_NOTIFY_INVALID_SYNTAX = 7,
  IKE_PAYLOAD_NOTIFY_INVALID_MESSAGE_ID = 9,
  IKE_PAYLOAD_NOTIFY_INVALID_SPI = 11,
  IKE_PAYLOAD_NOTIFY_NO_PROPOSAL_CHOSEN = 14,
  IKE_PAYLOAD_NOTIFY_INVALID_KE_PAYLOAD = 17,
  IKE_PAYLOAD_NOTIFY_AUTHENTICATION_FAILED = 24,
  IKE_PAYLOAD_NOTIFY_SINGLE_PAIR_REQUIRED = 34,
  IKE_PAYLOAD_NOTIFY_NO_ADDITIONAL_SAS = 35,
  IKE_PAYLOAD_NOTIFY_INTERNAL_ADDRESS_FAILURE = 36,
  IKE_PAYLOAD_NOTIFY_FAILED_CP_REQUIRED = 37,
  IKE_PAYLOAD_NOTIFY_TS_UNACCEPTABLE = 38,
  IKE_PAYLOAD_NOTIFY_INVALID_SELECTORS = 39,
  IKE_PAYLOAD_NOTIFY_TEMPORARY_FAILURE = 43,
  IKE_PAYLOAD_NOTIFY_CHILD_SA_NOT_FOUND = 44,
  
  // Informational types
  IKE_PAYLOAD_NOTIFY_INITIAL_CONTACT = 16384,
  IKE_PAYLOAD_NOTIFY_SET_WINDOW_SIZE = 16385,
  IKE_PAYLOAD_NOTIFY_ADDITIONAL_TS_POSSIBLE = 16386,
  IKE_PAYLOAD_NOTIFY_IPCOMP_SUPPORTED = 16387,
  IKE_PAYLOAD_NOTIFY_NAT_DETECTION_SOURCE_IP = 16388,
  IKE_PAYLOAD_NOTIFY_NAT_DETECTION_DESTINATION_IP = 16389,
  IKE_PAYLOAD_NOTIFY_COOKIE = 16390,
  IKE_PAYLOAD_NOTIFY_USE_TRANSPORT_MODE = 16391,
  IKE_PAYLOAD_NOTIFY_HTTP_CERT_LOOKUP_SUPPORTED = 16392,
  IKE_PAYLOAD_NOTIFY_REKEY_SA = 16393,
  IKE_PAYLOAD_NOTIFY_ESP_TFC_PADDING_NOT_SUPPORTED = 16394,
  IKE_PAYLOAD_NOTIFY_NON_FIRST_FRAGMENTS_ALSO = 16395
} notify_msg_type_t;

#define IKE_PAYLOAD_COOKIE_MAX_LEN 64

/**
  * ID payload (p. 87)
  *
                       1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  | Next Payload  |C|  RESERVED   |         Payload Length        |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |   ID Type     |                 RESERVED                      |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                                                               |
  ~                   Identification Data                         ~
  |                                                               |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

           Figure 11:  Identification Payload Format
  */
typedef enum {
  IKE_ID_IPV4_ADDR = 1,
    // A single four (4) octet IPv4 address.

  IKE_ID_FQDN,
    /*
      A fully-qualified domain name string.  An example of an ID_FQDN
      is "example.com".  The string MUST NOT contain any terminators
      (e.g., NULL, CR, etc.). All characters in the ID_FQDN are ASCII;
      for an "internationalized domain name", the syntax is as defined
      in [IDNA], for example "xn--tmonesimerkki-bfbb.example.net".
    */

   IKE_ID_RFC822_ADDR,
    /*
      A fully-qualified RFC 822 email address string.  An example of a
      ID_RFC822_ADDR is "jsmith@example.com".  The string MUST NOT
      contain any terminators.  Because of [EAI], implementations would
      be wise to treat this field as UTF-8 encoded text, not as
      pure ASCII.
    */
    
   IKE_ID_IPV6_ADDR = 5,
    /*
      A single sixteen (16) octet IPv6 address.
    */
    
   IKE_ID_DER_ASN1_DN = 9,
    /*
      The binary Distinguished Encoding Rules (DER) encoding of an
      ASN.1 X.500 Distinguished Name [PKIX].
    */

   ID_DER_ASN1_GN,
    /*
      The binary DER encoding of an ASN.1 X.509 GeneralName [PKIX].
      */
      
   ID_KEY_ID
    /*
      An opaque octet stream that may be used to pass vendor-
      specific information necessary to do certain proprietary
      types of identification.} id_type_t;
      */
} id_type_t;


typedef struct {
  uint8_t id_type;  /* id_type_t */
  uint8_t clear1;
  uint16_t clear2;
} ike_id_payload_t;


#define SET_IDPAYLOAD(id_payload, payload_arg, id, payload, payload_len)  \
  id_payload = (ike_id_payload_t *) (payload_arg).start;        \
   /* Clear the RESERVED area */                                \
  *((uint32_t *) id_payload) = 0;                               \
  *((uint8_t *) id_payload) = id;                               \
  payload_arg.start += sizeof(ike_id_payload_t);                \
  memcpy(payload_arg.start, (uint8_t *) payload, payload_len);  \
  payload_arg.start += payload_len


/**
  * Traffic selector (TS) payload (p. 103)
  *
                       1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  | Next Payload  |C|  RESERVED   |         Payload Length        |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  | Number of TSs |                 RESERVED                      |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                                                               |
  ~                       <Traffic Selectors>                     ~
  |                                                               |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

           Figure 19:  Traffic Selectors Payload Format
  */
#define SET_TSPAYLOAD(ts_payload, no_of_ts)         \
           *((uint32_t *) (ts_payload)) = 0;              \
           (ts_payload)->number_of_ts = (no_of_ts)
typedef struct {
  uint8_t number_of_ts;
  uint8_t clear1;
  uint16_t clear2;
} ike_payload_ts_t;


/**
  * Traffic selector (p. 105)
  *
                       1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |   TS Type     |IP Protocol ID*|       Selector Length         |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |           Start Port*         |           End Port*           |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                                                               |
  ~                         Starting Address*                     ~
  |                                                               |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                                                               |
  ~                         Ending Address*                       ~
  |                                                               |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

              Figure 20: Traffic Selector
  */
// Only IPv6 type selectors are supported
#define IKE_PAYLOADFIELD_TS_NL_ANY_PROTOCOL 0
#define IKE_PAYLOADFIELD_TS_IPV6_ADDR_RANGE 8
#define IKE_PAYLOADFIELD_TS_TYPE IKE_PAYLOADFIELD_TS_IPV6_ADDR_RANGE
#define IKE_PAYLOADFIELD_TS_SELECTOR_LEN (sizeof(ike_ts_t))
#define SET_TSSELECTOR_INIT(ts)                                   \
              (ts)->ts_type = IKE_PAYLOADFIELD_TS_TYPE;           \
              (ts)->selector_len = uip_htons(sizeof(ike_ts_t))

#define SET_TSSAMEADDR(ts, addr)                                        \
              memcpy((ts)->start_addr.u8, addr, sizeof(uip_ip6addr_t));    \
              memcpy((ts)->end_addr.u8, addr, sizeof(uip_ip6addr_t))

#define GET_ADDRSETFROMTS(addrset, ts_src, ts_dst) \
              memcpy(&addrset->ip6addr_src_range_from, &ts_src->start_addr, sizeof(uip_ip6addr_t)); \
              memcpy(&addrset->ip6addr_src_range_to, &ts_src->end_addr, sizeof(uip_ip6addr_t)); \
              memcpy(&addrset->ip6addr_dst_range_from, &ts_dst->start_addr, sizeof(uip_ip6addr_t)); \
              memcpy(&addrset->ip6addr_dst_range_to, &ts_dst->end_addr, sizeof(uip_ip6addr_t)); \
              addrset->nextlayer_proto = ts_src->proto; \
              addrset->nextlayer_src_port_range_from = ts_src->start_port; \
              addrset->nextlayer_src_port_range_to = ts_src->end_port; \
              addrset->nextlayer_dst_port_range_from = ts_dst->start_port; \
              addrset->nextlayer_dst_port_range_to = ts_dst->end_port

#define IKE_PAYLOADFIELD_TS_PROTO_ANY 0
typedef struct {
  uint8_t ts_type;
  uint8_t proto; // nextlayer protocol
  uint16_t selector_len;
  uint16_t start_port;
  uint16_t end_port;
  uip_ip6addr_t start_addr;
  uip_ip6addr_t end_addr;
} ike_ts_t;


/**
  * Encrypted (SK) payload (p. 107)
  *
                       1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
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

           Figure 21:  Encrypted Payload Format
  */

#endif

/** @} */