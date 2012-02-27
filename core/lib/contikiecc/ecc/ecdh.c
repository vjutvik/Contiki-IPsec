/**
  * Encodes the public key beginning at start.
  */
u8_t *ecdh_encode_public_key(u32_t *start, NN_DIGIT *myPrvKey)
{
  u8_t *ptr = start;
  u16_t len = KEYDIGITS * NN_DIGIT_LEN;
  point_t pubKey;

  ecc_gen_public_key(&pubKey, myPrvKey);
  nn_encode(ptr, len, pubKey.x, KEYDIGITS);
  ptr += len;
  nn_encode(ptr, len, pubKey.y, KEYDIGITS);
  
  return ptr + len;
}


/**
  * Calculate the shared key
  *
  * \parameter shared_key Pointer to the shared key (the X coordinate of the resulting point). Must be 24 bytes long (192 bits).\
  * \parameter peerPubKey The public key (commonly that of the other party). 48 B long (2 * 192 bits)
  * \parameter myPrvKey The private key (commonly ours). 24 bytes long.
  */
void ecdh_get_shared_secret(u8_t *shared_key, point_t *peerPubKey, NN_DIGIT *myPrvKey) 
{
  // Multiplicate
  
  // Projective optimization disabled as of now since the *Z-functions have not been ported -Ville 111006
  //#ifdef PROJECTIVE
  //    call ECC.win_precompute_Z(PublicKey, baseArray, ZList);
  //    call ECC.win_mul_Z(&tempP, PrivateKey, baseArray, ZList);
  //#else
  point_t tempP;
  #ifdef SLIDING_WIN
    ecc_win_precompute(peerPubKey, baseArray);
    ecc_win_mul(&tempP, myPrvKey, baseArray);
  //#endif //PROJECTIVE
  #else  //SLIDING_WIN
    ecc_mul(&tempP, peerPubKey, myPrvKey);
  #endif  //SLIDING_WIN
  
  // Copy the shared key
  memcpy(shared_key, &tempP.x, 24);
}

