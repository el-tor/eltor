/* See LICENSE for licensing information. */
#ifndef TOR_PAYMENT_CIRCUIT_H
#define TOR_PAYMENT_CIRCUIT_H

#include "feature/payment/payment_profile.h"
#include "feature/payment/payment_schedule.h"

struct or_circuit_t;
struct relay_msg_t;
typedef struct payment_circuit_t payment_circuit_t;

typedef enum payment_circuit_result_t {
  PAYMENT_CIRCUIT_OK = 0,
  PAYMENT_CIRCUIT_UNKNOWN_PERIOD,
  PAYMENT_CIRCUIT_UNCONFIRMED,
  PAYMENT_CIRCUIT_CONFLICT,
  PAYMENT_CIRCUIT_EXPIRED,
  PAYMENT_CIRCUIT_CAPACITY,
  PAYMENT_CIRCUIT_OBSERVATION_PENDING,
  PAYMENT_CIRCUIT_INVALID,
  PAYMENT_CIRCUIT_CLOSED
} payment_circuit_result_t;

typedef enum payment_circuit_admission_t {
  PAYMENT_CIRCUIT_RESERVED,
  PAYMENT_CIRCUIT_ID_CONFLICT,
  PAYMENT_CIRCUIT_NO_CAPACITY
} payment_circuit_admission_t;

typedef enum payment_circuit_authorization_t {
  PAYMENT_CIRCUIT_AUTH_NONE,
  PAYMENT_CIRCUIT_AUTHORIZED,
  PAYMENT_CIRCUIT_CONSUMED
} payment_circuit_authorization_t;

typedef enum payment_circuit_event_t {
  PAYMENT_CIRCUIT_EVENT_REGISTERED,
  PAYMENT_CIRCUIT_EVENT_ADMISSION_PENDING,
  PAYMENT_CIRCUIT_EVENT_COMMITTED,
  PAYMENT_CIRCUIT_EVENT_START_REQUESTED,
  PAYMENT_CIRCUIT_EVENT_AUTHORIZED,
  PAYMENT_CIRCUIT_EVENT_ROUND_ACTIVE,
  PAYMENT_CIRCUIT_EVENT_RENEW_ADMITTED,
  PAYMENT_CIRCUIT_EVENT_RENEW_REFUSED,
  PAYMENT_CIRCUIT_EVENT_GRACE,
  PAYMENT_CIRCUIT_EVENT_EXPIRED,
  PAYMENT_CIRCUIT_EVENT_CLOSED
} payment_circuit_event_t;

typedef struct payment_circuit_charge_t {
  uint8_t decision[16], payment_hash[32], record_digest[32];
  uint64_t amount_msat;
  payment_circuit_authorization_t authorization;
} payment_circuit_charge_t;

typedef struct payment_circuit_round_t {
  uint8_t payment_id[32];
  uint64_t round;
  payment_circuit_charge_t charge;
  /* Unavailable windows are rendered '- -', not zero clocks. */
  bool window_available;
  uint64_t opens_in_ms, closes_in_ms;
} payment_circuit_round_t;

/* Complete copied snapshot, containing no MAC/exporter keys or fee preimage.
 * circuit_binding is the exact retained C, local to this relay's verifier.
 * Control owner supplies instance/handle and formats multiline responses.
 * pending maps STATE to ADMISSION_PENDING instead of the initial phase enum.
 */
typedef struct payment_circuit_snapshot_t {
  payment_profile_policy_t policy;
  uint8_t terms[32], initial_allocation[32], allocation[32];
  uint8_t circuit_binding[32], request_digest[32];
  uint64_t revision, period, first_round, current_round, elapsed_ms;
  uint64_t constructed_elapsed_ms, commit_elapsed_ms;
  uint64_t setup_remaining_ms, enforcement_remaining_ms;
  uint64_t admission_remaining_ms;
  payment_schedule_phase_t phase;
  bool pending, commit_clock_available;
  payment_circuit_charge_t fee;
  payment_circuit_round_t rounds[10];
} payment_circuit_snapshot_t;

typedef void (*payment_circuit_event_cb_t)(struct or_circuit_t *circ,
                                          payment_circuit_event_t event);
/* Set once by the privileged control subsystem. Callback must not call wallets
 * or reenter mutations. It assigns local handles and emits revisioned hints. */
void payment_circuit_set_event_callback(payment_circuit_event_cb_t callback);
/* Inactive until final operator integration. Snapshot these exact accepted
 * terms before queuing work; NULL policy allows base free admission only.
 * This never resets any process resource owner or existing circuit policy. */
int payment_circuit_configure_construction(bool enabled,
                           const payment_profile_policy_t *policy);
bool payment_circuit_construction_policy(payment_profile_policy_t *out,
                                          bool *paid_candidate);
bool payment_circuit_requires_payment(const struct or_circuit_t *circ);

/* The sole construction entry point. Requires an explicitly enabled profile,
 * authenticated circuit-local keys, immutable accepted local policy and exact
 * validated initial construction material. No caller can infer these from a
 * controller assertion or a subsequently received COMMIT. No current runtime
 * producer enables the profile gate; capability/config integration owns that.
 */
payment_circuit_result_t payment_circuit_attach(
                          struct or_circuit_t *circ,
                          const payment_profile_policy_t *accepted_policy,
                          const uint8_t initial_ids[10][32],
                          const uint8_t handshake_payment_hash[32],
                          uint64_t constructed_ms, uint64_t now_ms);
/* Close disables timers and paid eligibility; free also releases bounded state.
 * Control inventory removes handles on CLOSED, before the circuit is freed. */
void payment_circuit_close(struct or_circuit_t *circ);
void payment_circuit_free(struct or_circuit_t *circ);
bool payment_circuit_present(const struct or_circuit_t *circ);
uint64_t payment_circuit_revision(const struct or_circuit_t *circ);

/* Recognized, already decrypted relay requests only. This checks direction,
 * StreamID, exact codec/MAC, accepted construction and immutable operations.
 * Correctly framed requests may create bounded pending admission, never wallet
 * work or paid capacity. Replies use ordinary RELAY and fresh circuit crypto.
 * Return 0 on handled/drop; a negative value requests circuit closure.
 */
int payment_circuit_handle_relay(struct or_circuit_t *circ,
                                 const struct relay_msg_t *msg,
                                 uint64_t now_ms);

/* Strictly read-only: no timer advancement, reservation, reply or activation.
 * OBSERVATION_PENDING asks the caller to retry after the independent timer
 * performs a due state transition; no funded activation is projected as real.
 * Callers enforce control authority and shared query budgets before reading.
 */
payment_circuit_result_t payment_circuit_get_admission(
                         const struct or_circuit_t *circ, uint64_t period,
                         uint64_t now_ms, payment_circuit_snapshot_t *out);
payment_circuit_result_t payment_circuit_get_registration(
                         const struct or_circuit_t *circ, uint64_t period,
                         uint64_t now_ms, payment_circuit_snapshot_t *out);

/* Control owner validates authenticated verifier role + instance/relay handle.
 * Decision identity and immutable request digest are checked here. Exact replay
 * is resolved before new-work deadline checks, with no reply/timer side effect.
 */
payment_circuit_result_t payment_circuit_decide(
                         struct or_circuit_t *circ, uint64_t period,
                         const uint8_t request_digest[32],
                         const uint8_t decision[16],
                         payment_circuit_admission_t result, uint64_t now_ms);
/* Controller also checks the canonical authorization record digest, whose
 * instance/handle fields it owns. This module checks exact registration,
 * expected amount, hash shape, original windows and immutable decision replay.
 */
payment_circuit_result_t payment_circuit_authorize(
                         struct or_circuit_t *circ, uint64_t round,
                         const payment_circuit_charge_t *authorization,
                         uint64_t now_ms);
/* Driven by the circuit timer/input transitions, never GET. */
void payment_circuit_tick(struct or_circuit_t *circ, uint64_t now_ms);
/* False before verified START + fee/round authorization and during grace. */
bool payment_circuit_paid_active(const struct or_circuit_t *circ);
/* Read-only time-aware gate; due timer transitions may revoke permission but
 * cannot grant a new funded activation before the real timer advances. */
bool payment_circuit_data_active(const struct or_circuit_t *, uint64_t now_ms);

#endif /* !defined(TOR_PAYMENT_CIRCUIT_H) */
