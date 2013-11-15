#ifndef __IPSEC_PROJECT_H__
#define __IPSEC_PROJECT_H__

//#include "project-conf.h"

/* Extra uIP logging */
#undef UIP_CONF_LOGGING
#define UIP_CONF_LOGGING 		0

#ifdef UIP_CONF_BUFFER_SIZE
#undef UIP_CONF_BUFFER_SIZE
#endif
#define UIP_CONF_BUFFER_SIZE	800 // This option can be set in various platform specific header files as well

#ifdef SICSLOWPAN_CONF_FRAG
#undef SICSLOWPAN_CONF_FRAG
#endif
#define SICSLOWPAN_CONF_FRAG	1


#define WITH_IPV6 						1
#define UIP_CONF_IPV6 				1
  
/* IPsec configuration */
/* Enabling ESP is equal to enabling to IPsec. Note that AH is not supported! */
#define WITH_CONF_IPSEC_ESP             1

/* The IKE subsystem is optional if the SAs are manually configured */
#define WITH_CONF_IPSEC_IKE             1

/*
 * Manual SA configuration allows you as developer to create persistent SAs in the SAD.
 * This is probably what you want to use if WITH_CONF_IPSEC_IKE is set 0, but please note
 * that both features can be used simultaneously on a host as per the IPsec RFC.
 *
 * The manual SAs can be set in the function sad_conf()
 */
#define WITH_CONF_MANUAL_SA 	0

/**
	* Configuring an AES implementation
	*
	*	The only current implementation is that provided by the MIRACL -library. In the future
	* this can be extended with an interface to the CC2420 radio module which is equipped with 
	* an AES hardware implementation.
	*/
#define CRYPTO_CONF_AES miracl_aes //cc2420_aes

/**
	* TODO: Remove the IPSEC_CONF -identifiers below once asserted it's safe 
	*/
/* Configuring a cipher block mode of operation (encryption/decryption) */
//#define IPSEC_CONF_BLOCK aesctr
/* Configuring a cipher block MAC mode of operation (authentication) */
//#define IPSEC_CONF_MAC aesxcbc_mac

#endif