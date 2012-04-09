/**
  * IKEv2 ID 
  */
extern const uint8_t ike_auth_sharedsecret[32];
extern const uint8_t ike_id[16];

extern void auth_psk(uint8_t transform, prf_data_t *auth_data);
