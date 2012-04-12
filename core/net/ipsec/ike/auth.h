/**
  * IKEv2 ID 
  */
extern const uint8_t ike_auth_sharedsecret[32];
extern const uint8_t ike_id[16];

extern void auth_psk(uint8_t transform, prf_data_t *auth_data);


/**
  * Authentication methods used in the IKE AUTH payload
  */
typedef enum {
     IKE_AUTH_METHOD_RSA_SIG = 1,
    /*
        Computed as specified in Section 2.15 using an RSA private key
        with RSASSA-PKCS1-v1_5 signature scheme specified in [PKCS1]
        (implementers should note that IKEv1 used a different method for
        RSA signatures).  To promote interoperability, implementations
        that support this type SHOULD support signatures that use SHA-1
        as the hash function and SHOULD use SHA-1 as the default hash
        function when generating signatures.  Implementations can use the
        certificates received from a given peer as a hint for selecting a
        mutually understood hash function for the AUTH payload signature.
        Note, however, that the hash algorithm used in the AUTH payload
        signature doesn't have to be the same as any hash algorithm(s)
        used in the certificate(s).
      */
      
     IKE_AUTH_SHARED_KEY_MIC,
      /*
        Shared Key Message Integrity Code
        Computed as specified in Section 2.15 using the shared key
        associated with the identity in the ID payload and the negotiated
        PRF.
       */
       
     IKE_AUTH_DSS_SIG
      /*
        Computed as specified in Section 2.15 using a DSS private key
        (see [DSS]) over a SHA-1 hash.
      */
} ike_auth_type_t;
