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
PROCESS(bob_process, "Alice process");
PROCESS(startup_process, "Statup Process");
AUTOSTART_PROCESSES(&startup_process);
/*---------------------------------------------------------------------------*/
//static NN_DIGIT r[NUMWORDS];
//static NN_DIGIT s[NUMWORDS];

point_t pbkey_alice;
NN_DIGIT prKey_alice[NUMWORDS];

static void abc_recv(struct abc_conn *c);
static const struct abc_callbacks abc_call = {abc_recv};
static struct abc_conn abc;

/*---------------------------------------------------------------------------*/
PROCESS_THREAD(startup_process, ev, data)
{
  PROCESS_BEGIN();

  memset(prKey_alice, 0, NUMWORDS*NN_DIGIT_LEN);

  memset(pbkey_alice.x, 0, NUMWORDS*NN_DIGIT_LEN);
  memset(pbkey_alice.y, 0, NUMWORDS*NN_DIGIT_LEN);

//  memset(r, 0, NUMWORDS*NN_DIGIT_LEN);
//  memset(s, 0, NUMWORDS*NN_DIGIT_LEN);

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

  prKey_alice[5] = 0x00000000;
  prKey_alice[4] = 0xc36e3e96;
  prKey_alice[3] = 0xc26c3d91;
  prKey_alice[2] = 0xc7ec7db1;
  prKey_alice[1] = 0xd7e47933;
  prKey_alice[0] = 0x16020c0d;

  /* Initialize ecc. */
  ecc_init();

  /* Initialize ecdsa with Alice's public key */
  ecdsa_init(&pbkey_alice);

  button_sensor.configure(SENSORS_ACTIVE, 1); 
  process_start(&bob_process, NULL);

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
static void
random_data(void *ptr, uint16_t len)
{
  
  uint16_t i;
  for(i=0; i<len; i++) {
    random_init(100);
    ((uint8_t *)(ptr))[i] = rand() % 100; 
  }
}
/*---------------------------------------------------------------------------*/
static void bacast_signed_message()
{
#define MSG_LEN 20
  msg_header_t * header;
  uint8_t *data;

  packetbuf_clear();
  header = (msg_header_t *)(packetbuf_dataptr());
  data = (uint8_t *)(header + 1);
  random_data(data, MSG_LEN);
  hton_uint16(&header->data_len, MSG_LEN);
  ecdsa_sign(data, MSG_LEN, header->r, header->s, prKey_alice);
  packetbuf_set_datalen(sizeof(msg_header_t) + MSG_LEN);
  abc_send(&abc);
}
/*---------------------------------------------------------------------------*/
static void
abc_recv(struct abc_conn *c)
{

}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(bob_process, ev, data)
{
  PROCESS_EXITHANDLER(abc_close(&abc);)
  PROCESS_BEGIN();

  abc_open(&abc, 128, &abc_call);
  while(1) {
    PROCESS_WAIT_EVENT_UNTIL(ev == sensors_event && data == &button_sensor);
    bacast_signed_message();
    printf("message sent.\n");
  }
  
  
  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
