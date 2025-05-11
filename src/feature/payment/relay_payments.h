/**
 * @file relay_payments.h
 * @brief Header for ElTor relay payment functionality
 **/

#ifndef RELAY_PAYMENTS_H
#define RELAY_PAYMENTS_H

#include "feature/payment/relay_payments_st.h"
#include "lib/container/smartlist.h"

/* Free functions */
void relay_payment_item_free_(relay_payment_item_t *item);
#define relay_payment_item_free(val) \
  FREE_AND_NULL(relay_payment_item_t, relay_payment_item_free_, (val))

void relay_payments_free_(relay_payments_t *payments);
#define relay_payments_free(val) \
  FREE_AND_NULL(relay_payments_t, relay_payments_free_, (val))

/* Creation functions */
relay_payment_item_t *relay_payment_item_new(void);
relay_payments_t *relay_payments_new(void);
void relay_payments_add_item(relay_payments_t *payments,
                             relay_payment_item_t *item);

/* Clone/copy functions */
relay_payment_item_t *relay_payment_item_clone(const relay_payment_item_t *item);
relay_payments_t *relay_payments_clone(const relay_payments_t *payments);

/* Search/query functions */
relay_payment_item_t *relay_payments_find_by_fingerprint(const relay_payments_t *payments, const char *fingerprint);
relay_payment_item_t *relay_payments_find_by_hop_num(const relay_payments_t *payments, int hop_num);

/* Validation functions */
int relay_payment_item_is_valid(const relay_payment_item_t *item);

void log_relay_payment(const relay_payment_item_t *payment_item);

#endif /* !defined(RELAY_PAYMENTS_H) */
