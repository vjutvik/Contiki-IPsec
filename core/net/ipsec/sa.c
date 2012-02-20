#include <contiki.h>

/**
  * Additional KEYMAT length of each "encr" transform
  *
  * The length of the keying material (KEYMAT) for any given encryption transform is dependent
  * upon:
  *   > If the encryption transform is of variable key length: Attribute as given by the IKEv2 negotiation
  *   > If the encryption transform is of fixed key length: Key size is determined solely by the transform type
  *   > Additional requirements (e.g. AES-CTR also expects a nonce in addition to its key: key material (variable) + 4 bytes (nonce)
  *
  * The keymat length of any "encr" transform is defined as follows:
  *   Length specified in key length attribute + sa_encr_keymat_extralen[encr transform id]
  *
  * This framework is believed to suit all "encr" transforms defined for IKEv2 and IPsec, with the exception of those having 
  * "default key lengths" as described in RFC 5996, p. 85:
  
     "Some transforms allow variable-length keys, but also specify a default key length if the attribute is not included.
      For example, these transforms include ENCR_RC5 and ENCR_BLOWFISH."
  
  */
const u8_t sa_encr_keymat_extralen[] =
{
  0,  // NOT IN USE
  0,  // NOT IN USE
  0,  // NOT IN USE
  0,  // 3DES. NOT IN USE
  0,  // NOT IN USE
  0,  // NOT IN USE
  0,  // NOT IN USE 
  0,  // NOT IN USE
  0,  // NOT IN USE
  0,  // NOT IN USE
  0,  // NOT IN USE
  0,  // NULL
  0,  // AES CBC. Completely determined by the key length attribute.
  4,  // AES CTR. Nonce length is 4 byte (RFC 3686, section 5.1)
};


/**
  * IV size in bytes of each encryption transform.
  *
  * This includes IVs of block as well as stream ciphers. In the former case
  * the IV size is also the same as the transform's block size.
  */
const u8_t sa_encr_ivlen[] = 
{ 
  0,
  0,
  0,
  8,  // 3DES
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,  // NULL
  16,  // AES CBC
  8,  // AES CTR. See RFC 3686, section 4
};


// Authenticator lengths (output lengths) of the PRFs in bytes.
// The input data must be of the same length or longer. When sourcing data for KEYMAT, the length must be equal.
//
// THe ouput length (authenticator length) is also the preferred input length.
const u8_t sa_prf_keymatlen[] = 
{
  0,
  0,            // MD5
  20,           // SHA1
  0,
  0,            // AES128
};


/**
  * KEYMAT length of each integrity/auth transform in bytes.
  *
  * As of RFC 5996, no transform of type 2 nor 3 uses variable key length (p. 85). The same passage also recommends this as the
  * future behaviour of type 2 and 3 transforms.
  */
const u8_t sa_integ_keymatlen[] = 
{ 
  0,
  12, // MD5, not implemented as of now
  20, // SHA1_96
  0,  
  0,
  16  // AES_XCBC_MAC_96
};

/**
  * Initialize an SA to default values
  */
/*
void sa_init_sa(sa_t *sa) {
  
}

// Constructor. Initializes sa_proposal_t.
void sa_proposal_new(sa_proposal_t *proposal) {
  LIST_STRUCT_INIT(proposal, transforms);
  list_init(proposal->transforms);
}
*/

