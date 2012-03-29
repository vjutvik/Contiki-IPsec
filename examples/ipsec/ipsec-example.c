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

#include "contiki.h"
#include "uip.h"
#include "ipsec.h"

#include <stdio.h> /* For printf() */

// test start

#include "border-router.h"
#include "net/uip-ds6.h"
#include "net/uip.h"

PROCESS(ipsec_example_process, "IPsec Example");
//AUTOSTART_PROCESSES(&ipsec_example_process);

PROCESS_NAME(border_router_process);
PROCESS_NAME(border_router_cmd_process);
PROCESS_NAME(webserver_nogui_process);

#if WEBSERVER==0
/* No webserver */
AUTOSTART_PROCESSES(&border_router_process, &border_router_cmd_process, &ipsec_example_process);
#else
AUTOSTART_PROCESSES(&border_router_process, &border_router_cmd_process,
		    &webserver_nogui_process, &ipsec_example_process);
#endif

// test end

#define DEBUG 1
#if DEBUG
#include <stdio.h>
#define PRINTF(...) printf(__VA_ARGS__)
#define PRINT6ADDR(addr) PRINTF(" %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x ", ((u8_t *)addr)[0], ((u8_t *)addr)[1], ((u8_t *)addr)[2], ((u8_t *)addr)[3], ((u8_t *)addr)[4], ((u8_t *)addr)[5], ((u8_t *)addr)[6], ((u8_t *)addr)[7], ((u8_t *)addr)[8], ((u8_t *)addr)[9], ((u8_t *)addr)[10], ((u8_t *)addr)[11], ((u8_t *)addr)[12], ((u8_t *)addr)[13], ((u8_t *)addr)[14], ((u8_t *)addr)[15])
#define PRINTLLADDR(lladdr) PRINTF(" %02x:%02x:%02x:%02x:%02x:%02x ",(lladdr)->addr[0], (lladdr)->addr[1], (lladdr)->addr[2], (lladdr)->addr[3],(lladdr)->addr[4], (lladdr)->addr[5])
#else
#define PRINTF(...)
#define PRINT6ADDR(addr)
#define PRINTLLADDR(addr)
#endif

#define MOTE_PORT 1234
#define UIP_IP_BUF   ((struct uip_ip_hdr *)&uip_buf[UIP_LLH_LEN])
#define UIP_UDP_BUF  ((struct uip_udp_hdr *)&uip_buf[uip_l2_l3_hdr_len])
static struct uip_udp_conn *server_conn;

static void
tcpip_handler(void)
{
  char* data = uip_appdata; //+uip_ext_len;
  u16_t datalen = uip_datalen();// - uip_ext_len - uip_ext_end_len;

  if(uip_newdata()) {
    int i=0;

    uip_len = 0;

    // PRINTF("IPSEC-EXAMPLE before: %u", UIP_HTONS(server_conn->rport));

    uip_ipaddr_copy(&server_conn->ripaddr, &UIP_IP_BUF->srcipaddr);
    udp_bind(server_conn, UIP_HTONS(MOTE_PORT));
    server_conn->rport = UIP_UDP_BUF->srcport;

    // PRINTF("IPSEC-EXAMPLE after: %u", UIP_HTONS(server_conn->rport));


    for(i=0; i<datalen; i++) {
      data[i]++;
    }
    printf("Replied: %10s...\n", data);
    
    uip_udp_packet_send(server_conn, data, datalen);

    memset(&server_conn->ripaddr, 0, sizeof(server_conn->ripaddr));
    server_conn->rport = 0;
  }
}
#include "payload.h"
void ipsec_ex_transmit(void *data) {
  udp_bind(server_conn, UIP_HTONS(1234));
  uip_ip6addr(&server_conn->ripaddr, 0xaaaa, 0, 0, 0, 0, 0, 0, 1);
  server_conn->rport = UIP_HTONS(500);
  uip_udp_packet_send(server_conn, "hej", 3);  
  printf("IPsec example transmitted\n");
  printf("sizeof ike_payload_ike_hdr_t %d\n", sizeof(ike_payload_ike_hdr_t));
  printf("ike_payloadfield_ikehdr_exchtype_t %d\n", sizeof(ike_payloadfield_ikehdr_exchtype_t));
  printf("ike_payload_type_t %d\n", sizeof(ike_payload_type_t));
}

struct ctimer retrans_timer;

/*---------------------------------------------------------------------------*/
PROCESS_THREAD(ipsec_example_process, ev, data)
{
  PROCESS_BEGIN();

  border_router_set_mac((uint8_t *) &uip_lladdr.addr);

  /* new connection with remote host */
  printf("ipsec-example: calling udp_new\n");
  server_conn = udp_new(NULL, UIP_HTONS(0), NULL);
  udp_bind(server_conn, UIP_HTONS(MOTE_PORT));

  /* IKEv2 immediate transmit */
  ctimer_set(&retrans_timer, 1 * CLOCK_SECOND, &ipsec_ex_transmit, NULL);
  /*
  uip_ip6addr(&server_conn->ripaddr, 0xaaaa, 0, 0, 0, 0, 0, 0, 1);
  server_conn->rport = UIP_HTONS(500);
  uip_udp_packet_send(server_conn, "hej", 3);
  */
  /* wait for incoming data */
  /*
  while(1) {
    PROCESS_YIELD();
    if(ev == tcpip_event) {
      tcpip_handler();
    }
  }
  */
  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
