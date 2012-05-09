#ifndef __SPD_CONF_H__
#define __SPD_CONF_H__

#include "spd.h"

extern const spd_entry_t spd_table[];
extern const spd_proposal_tuple_t spdconf_ike_proposal[];
extern const spd_proposal_tuple_t spdconf_ike_open_proposal[];
//extern const spd_proposal_tuple_t my_ah_esp_proposal[];

// Section "3.4.  Key Exchange Payload" specifies an interdependence between the IKE proposal's
// MODP group and the KE payload. The following define states this common property.
#define SA_IKE_MODP_GROUP SA_DH_192_RND_ECP_GROUP
#define CURRENT_IKE_PROPOSAL spdconf_ike_proposal //spdconf_ike_open_proposal

#endif