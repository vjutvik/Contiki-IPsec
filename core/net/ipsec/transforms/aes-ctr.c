/**
 * \file
 *         AES-CTR block cipher mode of operation
 * \author
 *         Simon Duquennoy <simonduq@sics.se>
 *
 * RFC 3686
 *
 * Only 128 bit key sizes supported at this time
 */

#include <stdlib.h>
#include "sa.h"
#include "net/uip.h"
#include "encr.h"
#include "ipsec.h"
#include "transforms/aes-moo.h"

#define AESCTR_NONCESIZE 4
#define AESCTR_BLOCKSIZE 16
#define AESCTR_IVSIZE 8 // Same as in sa_encr_ivlen[encr_data->type]

/*---------------------------------------------------------------------------*/
static void
aes_ctr_init(u8_t *ctr_blk, const u8_t *key,
    const u8_t *iv, const u8_t *nonce)
{
  /* Set key */
  CRYPTO_AES.init(key);
  /* Initialize counter block */
  memcpy(ctr_blk, nonce, AESCTR_NONCESIZE);
  memcpy(ctr_blk + AESCTR_NONCESIZE, iv, AESCTR_IVSIZE);
  
  // Null counter
  memset(ctr_blk + AESCTR_NONCESIZE + AESCTR_IVSIZE, 0, 4);
  //*((u32_t *) ctr_blk + AESCTR_NONCESIZE + AESCTR_IVSIZE) = UIP_HTONL(1);

/*
  printf("ctr_init blk:\n");
  memprint(ctr_blk, 15);*/
}
/*---------------------------------------------------------------------------*/

static void
aes_ctr_step(u8_t *ctr_blk, u8_t *data, u16_t ctr, int len)
{
  // Set the counter in ctr_blk
  ctr = uip_htons(ctr);
  memcpy(ctr_blk + AESCTR_NONCESIZE + AESCTR_IVSIZE + 2, &ctr, sizeof(ctr));

/*
  printf("ctr_step blk:\n");
  memprint(ctr_blk, 15);
  */
  // tmp = ctr_blk 
  u8_t tmp[AESCTR_BLOCKSIZE];
  memcpy(tmp, ctr_blk, AESCTR_BLOCKSIZE);

  // AES encrypt tmp 
  CRYPTO_AES.encrypt(tmp);
  
  // buff ^= tmp
  int i;
  for (i = 0; i < len; i++)
    data[i] ^= tmp[i];
  
  // counter++
  /*
  count = UIP_HTONL(*((uint32_t*)(counter + AESCTR_NONCESIZE + IPSEC_IVSIZE)));
  *((uint32_t*)(counter + AESCTR_NONCESIZE + IPSEC_IVSIZE)) = UIP_HTONL(count + 1);
  */
  // FIX: Is this 32 bit casting violating byte boundaries?

  /*
  u32_t counter = uip_ntohl(*((u32_t *) (ctr_blk + AESCTR_NONCESIZE + AESCTR_IVSIZE)));
  *((u32_t *) (ctr_blk + AESCTR_NONCESIZE + AESCTR_IVSIZE)) = uip_htonl(counter + 1);
  */
}

/*---------------------------------------------------------------------------*/
void aes_ctr(encr_data_t *encr_data)
{
  u8_t ctr_blk[AESCTR_BLOCKSIZE]; //[IPSEC_KEYSIZE];
  
  u8_t *data = encr_data->encr_data + AESCTR_IVSIZE;
  u16_t datalen = encr_data->encr_datalen - AESCTR_IVSIZE;
  //printf("ctrl_blk: %p, encr_data->keymat: %p, encr_data->encr_data: %p, nonce: %p\n", ctr_blk, encr_data->keymat, encr_data->encr_data, &encr_data->keymat[encr_data->keylen]);
  aes_ctr_init(ctr_blk, encr_data->keymat, encr_data->encr_data, &encr_data->keymat[encr_data->keylen]);
  
  u16_t n = 0;
  for (n = 0; n * AESCTR_BLOCKSIZE < datalen; ++n) {
    u8_t len = AESCTR_BLOCKSIZE;
    if ((n + 1) * AESCTR_BLOCKSIZE > datalen) {
      //printf("diff: %u\n", (n + 1) * AESCTR_BLOCKSIZE - datalen);
      len = len - ((n + 1) * AESCTR_BLOCKSIZE - datalen);
    }
    aes_ctr_step(ctr_blk, &data[n * AESCTR_BLOCKSIZE], n + 1, len);   
  }
}
