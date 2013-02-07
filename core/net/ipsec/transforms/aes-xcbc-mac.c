/**
 * \file
 *         AES-XCBC Message Authentication Code mode of operation (RCF 3566)
 * \author
 *         Simon Duquennoy <simonduq@sics.se>
 *				 Vilhelm Jutvik <ville@imorgon.se>, adapted for IKEv2
 */

#include <string.h>
#include "net/uip.h"
#include "sa.h"
#include "ipsec.h"
#include "common_ipsec.h"
#include "transforms/integ.h"
#include "transforms/aes-moo.h"

#define XCBC_BLOCKLEN 16

/*---------------------------------------------------------------------------*/
static void
aes_xcbc_mac_init(uint8_t *prev, const uint8_t key[XCBC_BLOCKLEN])
{
  /* Set key */
  CRYPTO_AES.init(key);
  /* No previous block, set to 0 */
  memset(prev, 0, XCBC_BLOCKLEN);
}
/*---------------------------------------------------------------------------*/
static void
aes_xcbc_mac_step(uint8_t *prev, uint8_t buff[XCBC_BLOCKLEN])
{
  int i;
  /* prev ^= buff */
  for(i = 0; i < XCBC_BLOCKLEN; i++)
    prev[i] ^= buff[i];

  /* AES encrypt prev */
  CRYPTO_AES.encrypt(prev);
}
/*---------------------------------------------------------------------------*/
static void
aes_xcbc_mac_final_step(uint8_t *prev, uint8_t *buff, int len,
    const uint8_t *key2, const uint8_t *key3)
{
  int i;
  uint8_t tmp[XCBC_BLOCKLEN];
  /* the key is not the same if the last block isn't full */
  const uint8_t *key = (len == XCBC_BLOCKLEN) ? key2 : key3;
  /* tmp = buff */
  memcpy(tmp, buff, XCBC_BLOCKLEN);
  /* add padding if needed */
  for(i = 0; i < XCBC_BLOCKLEN - len; i++)
    tmp[len + i] = (i == 0) ? 0x80 : 0x00;

  /* lastinput ^= key */
  for(i = 0; i < XCBC_BLOCKLEN; i++)
    tmp[i] ^= key[i];

  /* run normal step on tmp */
  aes_xcbc_mac_step(prev, tmp);
}
/*---------------------------------------------------------------------------*/
void aes_xcbc(integ_data_t *data)
{
  // Steps according to RCF 3566: Section 4

  // Step 1
  CRYPTO_AES.init(data->keymat);
  uint8_t key[3][XCBC_BLOCKLEN];
  uint8_t pattern = 1;
  uint16_t i;
  for (i = 0; i < 3; ++i, ++pattern) {
    uint8_t j;
    for (j = 0; j < XCBC_BLOCKLEN; ++j) key[i][j] = pattern;
    
    CRYPTO_AES.encrypt((uint8_t *) &key[i]);
    //printf("AES-XCBC: Key %u\n", i);
    //memprint(&key[i], 16);
  }
  
  // Step 2-3
  uint8_t prev[XCBC_BLOCKLEN];
  aes_xcbc_mac_init(prev, key[0]);
  for(i = 0; i < (data->datalen - 1) / XCBC_BLOCKLEN; i++)
    aes_xcbc_mac_step(prev, data->data + i * XCBC_BLOCKLEN);
  
  // Step 4-5
  int len = data->datalen % XCBC_BLOCKLEN;
  aes_xcbc_mac_final_step(prev, data->data + i * XCBC_BLOCKLEN,
           len == 0 ? XCBC_BLOCKLEN : len, key[1], key[2]);
  memcpy(data->out, prev, IPSEC_ICVLEN);
}
/*---------------------------------------------------------------------------*/
