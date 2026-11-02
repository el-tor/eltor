/* Copyright (c) 2026, The El Tor Project. */
/* See LICENSE for licensing information. */
#ifndef TOR_CONTROL_PAYMENT_H
#define TOR_CONTROL_PAYMENT_H
#include "core/or/or.h"
#include "feature/payment/payment_circuit.h"
#include <stdarg.h>

#define CONTROL_PAYMENT_MAX_LINE 16384u
#define CONTROL_PAYMENT_MAX_LIVE 4096u
#define CONTROL_PAYMENT_MAX_TOMBSTONES 4096u
#define CONTROL_PAYMENT_MAX_SNAPSHOTS 4u
#define CONTROL_PAYMENT_PAGE_ROWS 128u
#define CONTROL_PAYMENT_RESPONSE_BYTES (32u * 1024u)
#define CONTROL_PAYMENT_OUTPUT_BYTES (256u * 1024u)
#define CONTROL_PAYMENT_OUTPUT_RESERVATION_BYTES (512u * 1024u)

typedef enum control_payment_role_t {
  CONTROL_PAYMENT_ORIGIN = 1,
  CONTROL_PAYMENT_RELAY
} control_payment_role_t;

typedef enum control_payment_command_t {
  CONTROL_PAYMENT_BIND = 1,
  CONTROL_PAYMENT_LIST,
  CONTROL_PAYMENT_INITIAL_PREPARE,
  CONTROL_PAYMENT_INITIAL_START,
  CONTROL_PAYMENT_INITIAL_GET,
  CONTROL_PAYMENT_INITIAL_REGISTRATION_GET,
  CONTROL_PAYMENT_INITIAL_REFRESH,
  CONTROL_PAYMENT_RENEW_PREPARE,
  CONTROL_PAYMENT_GET,
  CONTROL_PAYMENT_ADMISSION_GET,
  CONTROL_PAYMENT_ADMISSION_DECIDE,
  CONTROL_PAYMENT_REGISTRATION_GET,
  CONTROL_PAYMENT_AUTHORIZE
} control_payment_command_t;

typedef struct control_payment_request_t {
  control_payment_command_t command;
  uint8_t instance[16], handle[16], operation[16], nonce[16], decision[16];
  uint8_t cursor[16], request_digest[32], policy[55], terms[32], parent[32];
  uint8_t ids[10][32], payment_hash[32], record_digest[32];
  uint64_t period, first_round, round, amount_msat;
  uint32_t circuit_id;
  uint16_t hop;
  payment_circuit_admission_t admission;
  bool first_page, no_operation;
} control_payment_request_t;

/* Strict full-line parser, including command name and CRLF. No mutation. */
int control_payment_parse(const char *line, size_t len,
                           control_payment_request_t *out);
bool control_payment_is_command(const char *name);
/* The local authenticated control connection is the single privileged daemon
 * authority specified in control/renewal.md. Remote/unauthenticated peers cannot
 * query financial bindings, subscribe to hints or authorize incoming funds. */
bool control_payment_authority(const control_connection_t *conn);
int control_payment_handle_command(control_connection_t *conn,
                                   const char *line, size_t len);
/* Initialize before any enabled paid-profile construction; repeat is harmless.
 * Installs relay transition callback. No capability is enabled here. */
void control_payment_init(void);
/* Origin construction calls this at creation (not from BIND/GET). listed is
 * true only for an enabled paid profile. Handles never recycle in an instance.
 * Return -1 on finite inventory/counter exhaustion, before paid construction. */
int control_payment_register(circuit_t *circ, control_payment_role_t role,
                             uint16_t hops, bool listed);
int control_payment_binding(const circuit_t *circ, uint8_t instance[16],
                            uint8_t handle[16]);
uint64_t control_payment_revision(const circuit_t *circ);
void control_payment_origin_changed(origin_circuit_t *circ, const char *kind);
void control_payment_circuit_closed(circuit_t *circ);
void control_payment_connection_closed(control_connection_t *conn);
void control_payment_finished_flushing(control_connection_t *conn);
/* True only inside a bounded foundation response render. General legacy Tor
 * control output keeps its inherited behavior. These writers allocate nothing. */
bool control_payment_write_reply(control_connection_t *, int code, int separator,
                                  const char *body);
bool control_payment_vprintf_reply(control_connection_t *, int code,
    int separator, const char *format, va_list args);
/* Called only by the registered event's main-loop delivery path. */
void control_payment_queue_event(control_connection_t *conn, const char *line);
void control_payment_free_all(void);
/* Canonical record, fixed network byte order; no struct/JSON serialization. */
int control_payment_record_digest(uint8_t out[32], const uint8_t instance[16],
    const uint8_t handle[16], const uint8_t decision[16], uint64_t round,
    uint64_t amount_msat, const uint8_t payment_hash[32],
    const uint8_t terms[32], const uint8_t initial_allocation[32]);
#endif /* !defined(TOR_CONTROL_PAYMENT_H) */
