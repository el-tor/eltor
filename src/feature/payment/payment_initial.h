/* Copyright (c) 2026, The El Tor Project. */
/* See LICENSE for licensing information. */
#ifndef TOR_PAYMENT_INITIAL_H
#define TOR_PAYMENT_INITIAL_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
/* Authenticated construction material only; never a settlement assertion.
 * The proof is parsed for canonical framing and is never retained here. */
typedef struct payment_initial_material_t {
  uint8_t ids[10][32], fee_hash[32];
  bool valid;
} payment_initial_material_t;
int payment_initial_parse(payment_initial_material_t *out,
                           const uint8_t *payload, size_t len);
void payment_initial_clear(payment_initial_material_t *material);
#endif
