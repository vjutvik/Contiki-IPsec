#ifndef __IPSEC_PROJECT_H__
#define __IPSEC_PROJECT_H__

#include "project-conf.h"

/* AH and ESP can be enabled/disabled independently */
#define WITH_CONF_IPSEC_AH              0
#define WITH_CONF_IPSEC_ESP             0

/* The IKE subsystem is optional if the SAs are manually configured */
#define WITH_CONF_IKE                   0

/* Configuring an AES implementation */
#define CRYPTO_CONF_AES miracl_aes //cc2420_aes
/* Configuring a cipher block mode of operation (encryption/decryption) */
#define IPSEC_CONF_BLOCK aesctr
/* Configuring a cipher block MAC mode of operation (authentication) */
#define IPSEC_CONF_MAC aesxcbc_mac

#endif