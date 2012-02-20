#include "auth.h"
#include "ecc/ecc_sha1.h"

/**
  * \param msg Message to be hashed
  * \param len Length of msg
  * \param out Output address
  */
void sha1(prf_data_t *data) // prf_data_t
{ 
  SHA1Context ctx;
  sha1_reset(&ctx);
  sha1_update(&ctx, data->data, data->datalen);
  sha1_digest(&ctx, data->out);
}

/*
// TODO: Write HMAC version of SHA1
void hmac_sha1()  // integ_data_t
{
  
}*/