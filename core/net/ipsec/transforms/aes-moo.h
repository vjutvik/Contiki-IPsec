/**
 * \file
 *         Generic interfaces for AES and modes of operation
 *         (block cipher, MAC)
 * \author
 *         Simon Duquennoy <simonduq@sics.se>
 */
 
#ifndef __AES_MOO_H__
#define __AES_MOO_H__


#ifdef CRYPTO_CONF_AES
#define CRYPTO_AES CRYPTO_CONF_AES
#else
#define CRYPTO_AES default_aes
#endif

/**
	* TODO: Remove the IPSEC -identifiers below once asserted it's safe 
	*/

// #ifdef IPSEC_CONF_BLOCK
// #define IPSEC_BLOCK IPSEC_CONF_BLOCK
// #else
// #define IPSEC_BLOCK aesctr
// #endif

// #ifdef IPSEC_CONF_MAC
// #define IPSEC_MAC IPSEC_CONF_MAC
// #else
// #define IPSEC_MAC aesxcbc_mac
// #endif

struct aes_implem {
  void (*init)(const uint8_t *key);
  void (*encrypt)(uint8_t *buff);
  void (*decrypt)(uint8_t *buff);
};

// struct ipsec_encrypt_implem {
//   void (*encrypt)(uint8_t *buff, uint16_t bufflen, const uint8_t *iv);
//   void (*decrypt)(uint8_t *buff, uint16_t bufflen, const uint8_t *iv);
// };
// 
// struct ipsec_mac_implem {
//   void (*auth)(uint8_t *out, uint8_t *buff, uint16_t bufflen);
// };

extern struct aes_implem CRYPTO_AES;
// extern struct ipsec_encrypt_implem IPSEC_BLOCK;
// extern struct ipsec_mac_implem IPSEC_MAC;

#endif /* __AES_MOO_H__ */
