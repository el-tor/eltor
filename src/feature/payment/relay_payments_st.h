#ifndef RELAY_PAYMENTS_ST_H
#define RELAY_PAYMENTS_ST_H

#include <stdlib.h>
#include <string.h>
#include "lib/container/smartlist.h"


typedef struct {
  char *fingerprint;
  char *handshake_payment_hash;
  char *handshake_preimage;
  char *payhashes;
  char *wire_format;
} relay_payment_item_t;

/* A list of relay payment items */
typedef smartlist_t relay_payments_t;

#endif /* !defined(RELAY_PAYMENTS_ST_H) */
