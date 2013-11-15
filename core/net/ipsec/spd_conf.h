/**
 * \addtogroup ipsec
 * @{
 */

/**
 	* \file
 	* 			SPD configuration
	*	\details
  * 			This file contains functions for SPD configuration.
  * 			
  * 			All values and definitions described herein pertains to RFC 4301 (Security Architecture for IP) and
  * 			RFC 5996 (Internet Key Exchange Protocol Version 2). Sections of special interests are:
  * 			
  * 			RFC 4301: 4.4.1 (Security Policy Database)
  * 			RFC 5996: 3.3 (Security Association Payload)
  * 			
  * 			Please see spd.h for a quick overview of the data format.
	* \author
 	*				Vilhelm Jutvik <ville@imorgon.se>
  */

/*
 * Copyright (c) 2012, Vilhelm Jutvik.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * This file is part of the Contiki operating system.
 */

#ifndef __SPD_CONF_H__
#define __SPD_CONF_H__

#include "spd.h"

extern const spd_entry_t spd_table[];
extern const spd_proposal_tuple_t spdconf_ike_proposal[];
extern const spd_proposal_tuple_t spdconf_ike_open_proposal[];

// Section "3.4.  Key Exchange Payload" specifies an interdependence between the IKE proposal's
// MODP group and the KE payload. The following define states this common property.
#define SA_IKE_MODP_GROUP SA_DH_192_RND_ECP_GROUP
#define CURRENT_IKE_PROPOSAL spdconf_ike_proposal //spdconf_ike_open_proposal

#endif

/** @} */