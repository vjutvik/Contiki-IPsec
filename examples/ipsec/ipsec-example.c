/*
 * Copyright (c) 2006, Swedish Institute of Computer Science.
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
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is part of the Contiki operating system.
 *
 * $Id: hello-world.c,v 1.1 2006/10/02 21:46:46 adamdunkels Exp $
 */

/**
 * \file
 *         A simple UDP app receiving a string,
 *         incrementing the bytes and sending back.
 * \author
 *         Simon Duquennoy <simonduq@sics.se>
 */

#include <string.h>
#include "uip-udp-packet.h"
#include "contiki.h"
#include "uip.h"
#include "ipsec.h"

#include <stdio.h> /* For printf() */

// test start

//#include "border-router.h"
#include "net/uip-ds6.h"
#include "net/uip.h"

PROCESS(ipsec_example_process, "IPsec Example");

#if CONTIKI_TARGET_NATIVE
#include "border-router.h" 
PROCESS_NAME(border_router_process);
PROCESS_NAME(border_router_cmd_process);
AUTOSTART_PROCESSES(&border_router_process, &border_router_cmd_process, &ipsec_example_process);
#else
AUTOSTART_PROCESSES(&ipsec_example_process);
#endif

#define MOTE_PORT 1234
#define UIP_IP_BUF   ((struct uip_ip_hdr *)&uip_buf[UIP_LLH_LEN])
#define UIP_UDP_BUF  ((struct uip_udp_hdr *)&uip_buf[uip_l2_l3_hdr_len])
static struct uip_udp_conn *server_conn;

static void
tcpip_handler(void)
{
  char* data = uip_appdata; //+uip_ext_len;
  uint16_t datalen = uip_datalen();// - uip_ext_len - uip_ext_end_len;

  if(uip_newdata()) {
    int i=0;

    uip_len = 0;

    // PRINTF("IPSEC-EXAMPLE before: %u", UIP_HTONS(server_conn->rport));

    uip_ipaddr_copy(&server_conn->ripaddr, &UIP_IP_BUF->srcipaddr);
    udp_bind(server_conn, UIP_HTONS(MOTE_PORT));
    server_conn->rport = UIP_UDP_BUF->srcport;

    printf("Replied:\"");
    for(i = 0; i < datalen; i++) {
      printf("%c", ++data[i]);
    }
		printf("\"\n(length %u)\n", datalen);

    
	  uint32_t cpu = energest_type_time(ENERGEST_TYPE_CPU);
	  uint32_t transmit = energest_type_time(ENERGEST_TYPE_TRANSMIT);

    uip_udp_packet_send(server_conn, data, datalen);

	  cpu = energest_type_time(ENERGEST_TYPE_CPU) - cpu;
	  transmit = energest_type_time(ENERGEST_TYPE_TRANSMIT) - transmit;

		uint32_t arch_second = RTIMER_ARCH_SECOND;
		printf("CPU time: %u, TRANSMIT time: %u, arch second %u\n", cpu, transmit, arch_second);

    memset(&server_conn->ripaddr, 0, sizeof(server_conn->ripaddr));
    server_conn->rport = 0;
  }
}
#include "payload.h"
struct ctimer retrans_timer;


void ipsec_ex_transmit(void *data) {
//  udp_bind(server_conn, 0);
  uip_ip6addr(&server_conn->ripaddr, 0xaaaa, 0, 0, 0, 0, 0, 0, 1);
  server_conn->rport = UIP_HTONS(1234);
  uip_udp_packet_send(server_conn, "hej", 3);  
  printf("IPsec example transmitted\n");
  printf("sizeof ike_payload_ike_hdr_t %d\n", sizeof(ike_payload_ike_hdr_t));
  printf("ike_payloadfield_ikehdr_exchtype_t %d\n", sizeof(ike_payloadfield_ikehdr_exchtype_t));
  printf("ike_payload_type_t %d\n", sizeof(ike_payload_type_t));
  
  ctimer_set(&retrans_timer, 3 * CLOCK_SECOND, &ipsec_ex_transmit, NULL);
}


/*---------------------------------------------------------------------------*/
PROCESS_THREAD(ipsec_example_process, ev, data)
{
  PROCESS_BEGIN();

	#if CONTIKI_TARGET_NATIVE
	border_router_set_mac((uint8_t *) &uip_lladdr.addr);
	#endif
	
  /* new connection with remote host */
  printf("ipsec-example: calling udp_new\n");
  server_conn = udp_new(NULL, UIP_HTONS(0), NULL);
  udp_bind(server_conn, UIP_HTONS(MOTE_PORT));

  /*
	 * IKEv2 handshake
	 *
	 * Uncomment this block of code in order to transmit a packet on port 1234 to host aaaa::1 10 seconds after startup.
	 * This will cause the mote to initiate the IKEv2 negotiation (given that there exists such a PROTECT rule in the SPD
	 * for the traffic in question).
	 * 
	*/
/*  
  ctimer_set(&retrans_timer, 10 * CLOCK_SECOND, &ipsec_ex_transmit, NULL);

  uip_ip6addr(&server_conn->ripaddr, 0xaaaa, 0, 0, 0, 0, 0, 0, 1);
  server_conn->rport = UIP_HTONS(1234);
  uip_udp_packet_send(server_conn, "hello", 5);
*/

  /* wait for incoming data */
  while(1) {
    PROCESS_YIELD();
    if(ev == tcpip_event) {
      tcpip_handler();
    }
  }
  PROCESS_END();
}
/*---------------------------------------------------------------------------*/

