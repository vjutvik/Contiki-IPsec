#include "ecc.h"
#include "ecdsa.h"
#include "contiki.h"
#include "lib/rand.h"
#include "net/rime.h"
#include "dev/button-sensor.h"
#include "dev/leds.h"

#include "messages.h"

#include <stdio.h> /* For printf() */
#include <string.h>
/*---------------------------------------------------------------------------*/
PROCESS(bob_process, "Bob process");
PROCESS(startup_process, "Statup Process");
AUTOSTART_PROCESSES(&startup_process);
/*---------------------------------------------------------------------------*/

point_t pbkey_alice;
point_t pbkey_bob;
NN_DIGIT prKey_bob[NUMWORDS];

static void abc_recv(struct abc_conn *c);
static const struct abc_callbacks abc_call = {abc_recv};
static struct abc_conn abc;
/*---------------------------------------------------------------------------*/
static void
abc_recv(struct abc_conn *c)
{
  printf("Message received.\n");
  msg_header_t * header;
  uint8_t *data;
  uint16_t data_len;
  char i;

  header = (msg_header_t *)(packetbuf_dataptr());
  data_len = ntoh_uint16(&header->data_len);

  data = (uint8_t *)(header + 1);
  i = ecdsa_verify(data, data_len, header->r, header->s, &pbkey_alice);
  if(i==1) {
    leds_toggle(LEDS_GREEN);
  } else {
    leds_toggle(LEDS_RED);
  }
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(startup_process, ev, data)
{
  PROCESS_BEGIN();

  memset(prKey_bob, 0, NUMWORDS*NN_DIGIT_LEN);

  memset(pbkey_bob.x, 0, NUMWORDS*NN_DIGIT_LEN);
  memset(pbkey_bob.y, 0, NUMWORDS*NN_DIGIT_LEN);

  /* set public key for Alice */
  pbkey_alice.x[5] = 0x00000000;
  pbkey_alice.x[4] = 0x21961f69;
  pbkey_alice.x[3] = 0xf02d202b;
  pbkey_alice.x[2] = 0xa4b41f1a;
  pbkey_alice.x[1] = 0x0aa08a86;
  pbkey_alice.x[0] = 0xdf27908d;
    
  pbkey_alice.y[5] = 0x00000000;
  pbkey_alice.y[4] = 0x378e1278;
  pbkey_alice.y[3] = 0x62836d75;
  pbkey_alice.y[2] = 0x7acb7ca4;
  pbkey_alice.y[1] = 0x0dc0ad13;
  pbkey_alice.y[0] = 0x741e287c;

  /* Initialize ecc. */
  ecc_init();

  /* Initialize ecdsa with Alice's public key */
  ecdsa_init(&pbkey_alice);

  button_sensor.configure(SENSORS_ACTIVE, 1); 
  process_start(&bob_process, NULL);

  printf("signature size %d\n", 2*(NUMWORDS * NN_DIGIT_LEN));

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/

PROCESS_THREAD(bob_process, ev, data)
{
  PROCESS_EXITHANDLER(abc_close(&abc);)
  PROCESS_BEGIN();

  abc_open(&abc, 128, &abc_call);
  while(1) {
    PROCESS_WAIT_EVENT_UNTIL(ev == sensors_event && data == &button_sensor);
    printf("button clicked\n");
  }
  
  
  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
