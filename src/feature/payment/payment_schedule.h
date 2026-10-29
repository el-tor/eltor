/* See LICENSE for licensing information. */
#ifndef TOR_PAYMENT_SCHEDULE_H
#define TOR_PAYMENT_SCHEDULE_H
#include "feature/payment/payment_profile.h"
#include <stdbool.h>

typedef enum {
  PAYMENT_SCHEDULE_UNCOMMITTED,
  PAYMENT_SCHEDULE_COMMITTED,
  PAYMENT_SCHEDULE_WAIT_PAYMENT,
  PAYMENT_SCHEDULE_ACTIVE,
  PAYMENT_SCHEDULE_GRACE,
  PAYMENT_SCHEDULE_CLOSED,
  PAYMENT_SCHEDULE_EXPIRED
} payment_schedule_phase_t;

/* Live circuit clock/authorization state only. The caller must first validate
 * authenticated wire requests and durable verifier decisions. This object does
 * not look up payments or manufacture a settled/consumed ledger record. */
typedef struct payment_schedule_t {
  payment_profile_policy_t policy;
  uint64_t constructed_ms, last_ms, t0_ms, current_round, active_period;
  uint16_t authorized, next_authorized;
  payment_schedule_phase_t phase;
  bool committed, start_requested, fee_authorized, started, next_admitted;
} payment_schedule_t;

int payment_schedule_init(payment_schedule_t *s,
                          const payment_profile_policy_t *policy,
                          uint64_t now_ms);
/* Called only after the exact initial batch has a durable RESERVED decision. */
int payment_schedule_commit(payment_schedule_t *s, uint64_t now_ms);
/* Caller checks immutable START identity before invoking this operation. */
int payment_schedule_start(payment_schedule_t *s, uint64_t now_ms);
/* round zero is the one-time handshake authorization, even when zero priced.
 * Positive authorization requires an admitted allocation and the original
 * early/grace window. Caller enforces exact decision replay/conflict rules. */
int payment_schedule_authorize(payment_schedule_t *s, uint64_t round,
                               uint64_t now_ms);
/* Called only after authenticated next-batch validation and durable reservation. */
int payment_schedule_admit_next(payment_schedule_t *s, uint64_t period,
                                uint64_t now_ms);
/* Timer/transition entry point. Queries must not invoke this to cause activation;
 * the circuit's scheduled timer and actual input transitions own progression. */
void payment_schedule_tick(payment_schedule_t *s, uint64_t now_ms);
void payment_schedule_close(payment_schedule_t *s);
#endif
