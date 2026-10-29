/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2024, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file cpuworker.h
 * \brief Header file for cpuworker.c.
 **/

#ifndef TOR_CPUWORKER_H
#define TOR_CPUWORKER_H

int cpuworker_init(void);
void cpuworker_free_all(void);
void cpuworkers_rotate_keyinfo(void);

void cpuworker_consensus_has_changed(const networkstatus_t *ns);

struct workqueue_entry_t;
enum workqueue_reply_t;
enum workqueue_priority_t;
MOCK_DECL(struct workqueue_entry_t *, cpuworker_queue_work, (
                    enum workqueue_priority_t priority,
                    enum workqueue_reply_t (*fn)(void *, void *),
                    void (*reply_fn)(void *),
                    void *arg));

struct create_cell_t;
int assign_onionskin_to_cpuworker(or_circuit_t *circ,
                                  struct create_cell_t *onionskin);

uint64_t estimated_usec_for_onionskins(uint32_t n_requests,
                                       uint16_t onionskin_type);
void cpuworker_log_onionskin_overhead(int severity, int onionskin_type,
                                      const char *onionskin_type_name);
void cpuworker_cancel_circ_handshake(or_circuit_t *circ);

unsigned int cpuworker_get_n_threads(void);

#ifdef CPUWORKER_PRIVATE
#include "core/or/onion.h"
#include "core/crypto/onion_crypto.h"
#include "feature/payment/payment_initial.h"
#include "feature/payment/payment_workqueue.h"
#include "lib/evloop/workqueue.h"

typedef struct worker_state_t {
  int generation;
  server_onion_keys_t *onion_keys;
} worker_state_t;


/** Magic numbers to make sure our cpuworker_requests don't grow any
 * mis-framing bugs. */
#define CPUWORKER_REQUEST_MAGIC 0xda4afeed
#define CPUWORKER_REPLY_MAGIC 0x5eedf00d

/** A request sent to a cpuworker. */
typedef struct cpuworker_request_t {
  /** Magic number; must be CPUWORKER_REQUEST_MAGIC. */
  uint32_t magic;

  /** Flag: Are we timing this request? */
  unsigned timed : 1;
  /** If we're timing this request, when was it sent to the cpuworker? */
  struct timeval started_at;

  /** A create cell for the cpuworker to process. */
  create_cell_t create_cell;

  /**
   * A copy of this relay's consensus params that are relevant to
   * the circuit, for use in negotiation. */
  circuit_params_t circ_ns_params;
  /** Main-loop provisional resource reservation, frozen before enqueue. */
  bool payment_export_requested;
  uint64_t payment_native_queued_ms, payment_native_start_before_ms;

  /** The circuit ID for this handshake. */
  circid_t circuit_id;

  /** The next circuit ID for this handshake (for multi-hop tracking). */
  circid_t n_circuit_id;

  /* Turn the above into a tagged union if needed. */
} cpuworker_request_t;

/** A reply sent by a cpuworker. */
typedef struct cpuworker_reply_t {
  /** Magic number; must be CPUWORKER_REPLY_MAGIC. */
  uint32_t magic;

  /** True iff we got a successful request. */
  uint8_t success;

  /** Are we timing this request? */
  unsigned int timed : 1;
  /** What handshake type was the request? (Used for timing) */
  uint16_t handshake_type;
  /** When did we send the request to the cpuworker? */
  struct timeval started_at;
  /** Once the cpuworker received the request, how many microseconds did it
   * take? (This shouldn't overflow; 4 billion micoseconds is over an hour,
   * and we'll never have an onion handshake that takes so long.) */
  uint32_t n_usec;

  /** Output of processing a create cell
   *
   * @{
   */
  /** The created cell to send back. */
  created_cell_t created_cell;
  /** The keys to use on this circuit. */
  uint8_t keys[MAX_RELAY_KEY_MATERIAL_LEN];
  /** Length of the generated key material. */
  size_t keys_len;
  payment_profile_export_t payment_result;
  payment_initial_material_t initial_material;
  /** Input to use for authenticating introduce1 cells. */
  uint8_t rend_auth_material[DIGEST_LEN];
  /** Negotiated circuit parameters. */
  circuit_params_t circ_params;
} cpuworker_reply_t;

typedef struct cpuworker_job_u_t {
  or_circuit_t *circ;
  payment_work_t *payment_work;
  union {
    cpuworker_request_t request;
    cpuworker_reply_t reply;
  } u;
} cpuworker_job_t;

STATIC void cpuworker_onion_handshake_replyfn(void *work);
STATIC workqueue_reply_t cpuworker_onion_handshake_threadfn(void *state,
                                                          void *work);
#ifdef TOR_UNIT_TESTS
extern threadpool_t *threadpool;
extern uint32_t total_pending_tasks;
#endif
#endif /* defined(CPUWORKER_PRIVATE) */

#endif /* !defined(TOR_CPUWORKER_H) */

