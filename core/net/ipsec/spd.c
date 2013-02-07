/**
 * \addtogroup ipsec
 * @{
 */

/**
 * \file
 * 		The SPD's interface
 * \author
 *		Vilhelm Jutvik <ville@imorgon.se>
 *
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

/** @} */

#include "lib/list.h"
#include "spd.h"
#include "ipsec.h"
#include "common_ipsec.h"
#include "spd_conf.h"

/**
  * Return the SPD entry that applies to traffic of type \c addr
  *
  * \return the first entry (from the top) whose selector includes the address \c addr. NULL is returned if no such is found
  * (shouldn't happen because there *should* be a catch-all entry at the SPD's end).
  * 
  */
spd_entry_t *spd_get_entry_by_addr(ipsec_addr_t *addr)
{
  uint8_t n;
  for (n = 0; n < SPD_ENTRIES; ++n) {
    if (ipsec_a_is_member_of_b(addr, (ipsec_addr_set_t *) &spd_table[n].selector))
      return &spd_table[n];
  }
  PRINTF(IPSEC "Error: spd_get_entry_by_addr: Nothing found. You ought to have a final rule in the SPD table that catches all traffic. Please see the RFC.\n");
  return NULL;
}

/** @} */