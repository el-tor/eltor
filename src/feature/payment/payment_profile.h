/* See LICENSE for licensing information. */
#ifndef TOR_PAYMENT_PROFILE_H
#define TOR_PAYMENT_PROFILE_H

#include <stddef.h>
#include <stdbool.h>
#include "lib/malloc/malloc.h"
#include "lib/cc/torint.h"

/* Inactive codecs for the draft paid-hop v1 profile. These constants do not
 * advertise support or register commands. No native struct is serialized.
 */
#define PAYMENT_PROFILE_TERMS_LEN 55
#define PAYMENT_PROFILE_WIRE_LEN 463
#define PAYMENT_PROFILE_BODY_LEN 431
#define PAYMENT_PROFILE_ID_COUNT 10
#define PAYMENT_PROFILE_IDS_LEN 320
#define PAYMENT_PROFILE_ROUND_MS 60000

typedef enum {
  PAYMENT_PROFILE_RENEW = 224,
  PAYMENT_PROFILE_RENEWED = 225,
  PAYMENT_PROFILE_COMMIT = 226,
  PAYMENT_PROFILE_COMMITTED = 227,
  PAYMENT_PROFILE_START_STATUS = 228,
  PAYMENT_PROFILE_STARTED_STATUS = 229
} payment_profile_command_t;

typedef enum {
  PAYMENT_PROFILE_OK = 0,
  PAYMENT_PROFILE_ERR_LENGTH = -1,
  PAYMENT_PROFILE_ERR_HEADER = -2,
  PAYMENT_PROFILE_ERR_MAC = -3,
  PAYMENT_PROFILE_ERR_BODY = -4,
  PAYMENT_PROFILE_ERR_SEQUENCE = -5,
  PAYMENT_PROFILE_ERR_POLICY = -6,
  PAYMENT_PROFILE_ERR_TERMS = -7,
  PAYMENT_PROFILE_ERR_PARENT = -8
} payment_profile_result_t;

typedef struct payment_profile_policy_t {
  uint64_t rate_msat;
  uint32_t grace_ms;
  uint64_t paid_quota_bytes;
  uint64_t max_age_ms;
  uint32_t max_periods;
  uint64_t initial_handshake_fee_msat;
  uint32_t setup_timeout_ms;
} payment_profile_policy_t;

/* Exact zero-price candidate used only by the explicit TestingTorNetwork
 * ElTorFoundation option. It is not a production pricing default. */
payment_profile_policy_t payment_profile_testing_policy(void);

typedef struct payment_profile_keys_t {
  uint8_t context[32];
  uint8_t binding[32];
  uint8_t renew_request[32];
  uint8_t renew_reply[32];
  uint8_t start_request[32];
  uint8_t start_reply[32];
} payment_profile_keys_t;

/* Dedicated crypto result: valid only after authenticated handshake and
 * parameter negotiation. It is never traffic-key output or RPC data. */
typedef struct payment_profile_export_t {
  payment_profile_keys_t keys;
  bool valid;
} payment_profile_export_t;

void payment_profile_export_clear(payment_profile_export_t *result);
/* Move a successful, explicitly requested result into circuit-local storage.
 * Clears result on success or failure, never replaces existing keys. */
int payment_profile_export_take(payment_profile_keys_t **destination,
                                payment_profile_export_t *result,
                                bool requested);
void payment_profile_keys_free_(payment_profile_keys_t *keys);
#define payment_profile_keys_free(keys) \
  FREE_AND_NULL(payment_profile_keys_t, payment_profile_keys_free_, (keys))

typedef struct payment_profile_renew_t {
  uint64_t period, first_round, activation_ms;
  uint8_t nonce[16], terms[32], parent[32], ids[10][32];
} payment_profile_renew_t;

typedef struct payment_profile_renewed_t {
  uint8_t status; /* 0 ADMITTED through 9 CLOSING, per the wire draft. */
  uint64_t period, elapsed_ms, activation_ms, admit_before_ms, first_round;
  uint8_t nonce[16], request_digest[32], allocation[32], terms[32];
} payment_profile_renewed_t;

typedef struct payment_profile_commit_t {
  uint8_t nonce[16];
  payment_profile_policy_t policy;
  uint8_t allocation[32];
} payment_profile_commit_t;

typedef struct payment_profile_committed_t {
  uint8_t status; /* 0 COMMITTED through 5 CLOSED. */
  uint8_t nonce[16], request_digest[32], terms[32], allocation[32];
  uint32_t setup_remaining_ms;
} payment_profile_committed_t;

typedef struct payment_profile_start_t {
  uint8_t action; /* 0 START (round 1), 1 QUERY (round 0). */
  uint8_t nonce[16], terms[32], allocation[32];
  uint64_t round;
} payment_profile_start_t;

typedef struct payment_profile_started_t {
  uint8_t state; /* 0 UNCOMMITTED through 7 CONFLICT. */
  uint8_t nonce[16], request_digest[32], terms[32], allocation[32];
  uint64_t round, elapsed_ms, revision;
  uint32_t round_remaining_ms, enforcement_remaining_ms, setup_remaining_ms;
} payment_profile_started_t;

typedef struct payment_profile_message_t {
  payment_profile_command_t command;
  union {
    payment_profile_renew_t renew;
    payment_profile_renewed_t renewed;
    payment_profile_commit_t commit;
    payment_profile_committed_t committed;
    payment_profile_start_t start;
    payment_profile_started_t started;
  } u;
} payment_profile_message_t;

int payment_profile_policy_encode(uint8_t *out, size_t out_len,
                                  const payment_profile_policy_t *policy);
int payment_profile_policy_decode(payment_profile_policy_t *out,
                                  const uint8_t *wire, size_t len);
int payment_profile_ids_valid(const uint8_t ids[10][32]);

/* Standalone exporter primitive only: caller must supply the exact ntor-v3
 * transcripts and authenticated seed, after handshake/parameter success. This
 * module does not integrate with ntor or expose these keys to a controller.
 * Caller owns wiping the seed/transcripts and must clear keys on circuit loss.
 */
int payment_profile_derive_keys(payment_profile_keys_t *out,
                               const uint8_t seed[32],
                               const uint8_t *client_hdata, size_t client_len,
                               const uint8_t *server_hdata, size_t server_len);
void payment_profile_keys_clear(payment_profile_keys_t *keys);
int payment_profile_terms_digest(uint8_t out[32],
                                const payment_profile_policy_t *policy);
int payment_profile_initial_digest(uint8_t out[32], const uint8_t binding[32],
                                  const uint8_t terms[32],
                                  const uint8_t ids[10][32]);
int payment_profile_request_digest(uint8_t out[32],
                                  payment_profile_command_t command,
                                  const uint8_t *wire, size_t len);
int payment_profile_allocation_digest(uint8_t out[32],
                                     const uint8_t binding[32],
                                     const uint8_t *wire, size_t len);

/* Authenticate before semantic parsing; exact framing and reserved bytes are
 * checked. Decode clears output on failure. A sequence error on authenticated
 * RENEW is separately distinguishable so callers can construct BAD_SEQUENCE;
 * they must safely parse any echoed fields themselves. Context/state, nonce
 * freshness, ledger uniqueness, request/reply association and deadlines
 * need live-circuit validation; codec success never establishes admission.
 * key is the command's direction-specific key; binding is circuit-local C.
 */
int payment_profile_encode(uint8_t *out, size_t out_len,
                           const payment_profile_message_t *message,
                           const uint8_t key[32], const uint8_t binding[32]);
int payment_profile_decode(payment_profile_message_t *out,
                           payment_profile_command_t command,
                           const uint8_t *wire, size_t len,
                           const uint8_t key[32], const uint8_t binding[32]);
/* Stateless contextual checks only; no durable reservation or admission. */
int payment_profile_renew_check(const payment_profile_renew_t *request,
                               const payment_profile_policy_t *policy,
                               uint64_t expected_period,
                               const uint8_t terms[32],
                               const uint8_t parent[32]);

typedef enum {
  PAYMENT_CAPABILITY_START,
  PAYMENT_CAPABILITY_RENEW,
  PAYMENT_CAPABILITY_FREE
} payment_capability_kind_t;
/* Parse signed-descriptor token arguments. 1 = understood, 0 = unknown version,
 * -1 = malformed. No capability is usable until descriptor signatures pass.
 * FREE writes zero terms; paid capabilities preserve the exact 55 bytes. */
int payment_profile_parse_capability(uint8_t terms[55],
                                    payment_capability_kind_t kind,
                                    int argc, const char *const *argv);

#endif /* !defined(TOR_PAYMENT_PROFILE_H) */
