/* Copyright (c) 2026, The El Tor Project. */
/* See LICENSE for licensing information. */
#ifndef TOR_FREE_CAPACITY_H
#define TOR_FREE_CAPACITY_H

#include <stdbool.h>
#include <stdint.h>

/* Candidate resource_profile=1 limits, not measured production defaults. */
#define FREE_CAPACITY_CELL_RATE 2u
#define FREE_CAPACITY_CELL_BURST 128u
#define FREE_CAPACITY_LIFETIME_MS 600000u
#define FREE_CAPACITY_MAX_CIRCUITS 4096u
#define FREE_CAPACITY_ADMISSION_RATE 16u
#define FREE_CAPACITY_ADMISSION_BURST 32u
#define FREE_CAPACITY_CONN_ADMISSION_RATE 4u
#define FREE_CAPACITY_CONN_ADMISSION_BURST 8u
#define FREE_CAPACITY_BYTE_RATE (4u * 1048576u)
#define FREE_CAPACITY_BYTE_BURST (8u * 1048576u)
#define FREE_CAPACITY_CONN_BYTE_RATE 1048576u
#define FREE_CAPACITY_CONN_BYTE_BURST (2u * 1048576u)
#define FREE_CAPACITY_QUEUE_CELLS 32u
#define FREE_CAPACITY_QUEUE_BYTES (8u * 1048576u)
#define FREE_CAPACITY_QUEUE_AGE_MS 5000u

/* The caller owns these fixed-size objects and serializes every operation on
 * one relay event loop (or holds one lock). Time is absolute, nonwrapping
 * monotonic milliseconds, not wall-clock time. Never copy/reinitialize live state
 * to renew credit. No API allocates memory, sleeps or drops a cell. */
typedef struct free_capacity_bucket_t {
  uint64_t credit_milli;
  uint64_t last_ms;
  uint32_t rate;
  uint32_t burst;
} free_capacity_bucket_t;

typedef struct free_capacity_t {
  free_capacity_bucket_t admissions;
  free_capacity_bucket_t bytes;
  uint64_t last_ms;
  uint64_t received_bytes;
  uint64_t sent_bytes;
  uint32_t live_circuits;
  uint32_t queued_bytes;
} free_capacity_t;

typedef struct free_capacity_conn_t {
  free_capacity_t *owner;
  free_capacity_bucket_t admissions;
  free_capacity_bucket_t bytes;
} free_capacity_conn_t;

typedef struct free_capacity_circuit_t {
  free_capacity_t *owner;
  free_capacity_bucket_t cells;
  uint64_t admitted_ms;
  uint64_t queue_time[FREE_CAPACITY_QUEUE_CELLS];
  uint32_t queue_size[FREE_CAPACITY_QUEUE_CELLS];
  uint32_t queued_bytes;
  uint8_t queue_head;
  uint8_t queue_count;
  bool active;
  bool closing;
} free_capacity_circuit_t;

typedef enum free_capacity_result_t {
  FREE_CAPACITY_OK = 0,
  FREE_CAPACITY_WAIT,
  FREE_CAPACITY_CLOSE,
  FREE_CAPACITY_REFUSE,
  FREE_CAPACITY_BAD_STATE,
  FREE_CAPACITY_CLOCK_ERROR
} free_capacity_result_t;

void free_capacity_init(free_capacity_t *owner, uint64_t now_ms);
free_capacity_result_t free_capacity_conn_init(free_capacity_conn_t *connection,
                                              free_capacity_t *owner,
                                              uint64_t now_ms);
/* circuit must initially be zeroed and cannot be admitted twice while active.
 * Failed admission allocates/retains no new circuit state. */
free_capacity_result_t free_capacity_admit(free_capacity_conn_t *connection,
                                          free_capacity_circuit_t *circuit,
                                          uint64_t now_ms);
free_capacity_result_t free_capacity_check(free_capacity_circuit_t *circuit,
                                          uint64_t now_ms);
/* fixed_cells is actual ingress OR egress fixed-cell count, including control
 * and padding. bytes is actual serialized Tor link bytes, including variable
 * cells. One forwarded fixed cell requires two calls, receive then send.
 * Received traffic has already cost bandwidth: charge it even on CLOSE.
 * The actual link connection is explicit: a middle has distinct previous and
 * next connections, each with its own budget. It must have the same owner.
 * Connection state must persist for the real OR connection lifetime; circuits
 * retain only their process owner and need no second-link allocation.
 * Outbound WAIT consumes no credit (elapsed-time refill still applies); retry
 * only within bounded queues.
 * CLOSE requires closing the circuit, never skipping a stateful RELAY cell and
 * continuing. CLOSE is latched until teardown. A zero-cost call only checks
 * lifetime/state. */
free_capacity_result_t free_capacity_receive(free_capacity_circuit_t *circuit,
                                            free_capacity_conn_t *link,
                                            uint64_t fixed_cells,
                                            uint64_t bytes, uint64_t now_ms);
free_capacity_result_t free_capacity_send(free_capacity_circuit_t *circuit,
                                         free_capacity_conn_t *link,
                                         uint64_t fixed_cells,
                                         uint64_t bytes, uint64_t now_ms);
/* Link maintenance with no circuit attribution still costs the shared and
 * connection byte buckets. This cannot manufacture free circuit eligibility. */
free_capacity_result_t free_capacity_link_receive(
    free_capacity_conn_t *connection, uint64_t bytes, uint64_t now_ms);
free_capacity_result_t free_capacity_link_send(free_capacity_conn_t *connection,
                                              uint64_t bytes,
                                              uint64_t now_ms);
/* Reserve queue memory BEFORE allocating/copying a cell. Queue reservation
 * does not charge send tokens: send() does that exactly once before writing.
 * Only remove the head after successful send, or close the entire circuit.
 * Actual buffer/metadata capacity must be included in allocation_bytes. */
free_capacity_result_t free_capacity_queue_push(
    free_capacity_circuit_t *circuit, uint32_t allocation_bytes,
    uint64_t now_ms);
free_capacity_result_t free_capacity_queue_pop(free_capacity_circuit_t *circuit,
                                              uint64_t now_ms);
/* Idempotent release on every circuit teardown; does not refill any bucket.
 * The process object must outlive its connections and circuits. */
void free_capacity_release(free_capacity_circuit_t *circuit);

#endif /* !defined(TOR_FREE_CAPACITY_H) */
