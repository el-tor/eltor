/* Copyright (c) 2026, The El Tor Project. */
/* See LICENSE for licensing information. */
#ifndef TOR_PROTOCOL_BUDGET_H
#define TOR_PROTOCOL_BUDGET_H

#include <stdbool.h>
#include <stdint.h>

#define PROTOCOL_BUDGET_SLOTS 4096u
#define PROTOCOL_BUDGET_SLOT_BYTES (16u * 1024u)
#define PROTOCOL_BUDGET_ARENA_BYTES (64u * 1024u * 1024u)
#define PROTOCOL_BUDGET_CRYPTO_RATE 256u
#define PROTOCOL_BUDGET_CRYPTO_BURST 512u
#define PROTOCOL_BUDGET_RUNNING 32u
#define PROTOCOL_BUDGET_WAITING 128u
#define PROTOCOL_BUDGET_WAIT_MS 1000u

typedef struct protocol_budget_t protocol_budget_t;
typedef struct protocol_budget_slot_t protocol_budget_slot_t;
typedef struct protocol_budget_job_t protocol_budget_job_t;
typedef struct protocol_budget_memory_t protocol_budget_memory_t;

typedef enum protocol_budget_result_t {
  PROTOCOL_BUDGET_OK = 0,
  PROTOCOL_BUDGET_WAIT,
  PROTOCOL_BUDGET_REFUSE,
  PROTOCOL_BUDGET_EXPIRED,
  PROTOCOL_BUDGET_BAD_STATE,
  PROTOCOL_BUDGET_CLOCK_ERROR
} protocol_budget_result_t;

typedef struct protocol_budget_limits_t {
  uint32_t max_slots;
  uint32_t max_slot_bytes;
  uint32_t arena_bytes;
  uint32_t crypto_rate;
  uint32_t crypto_burst;
  uint32_t max_running;
  uint32_t max_waiting;
  uint32_t max_wait_ms;
} protocol_budget_limits_t;

typedef enum protocol_budget_slot_state_t {
  PROTOCOL_BUDGET_SLOT_UNUSED = 0,
  PROTOCOL_BUDGET_SLOT_LIVE,
  PROTOCOL_BUDGET_SLOT_TOMBSTONE
} protocol_budget_slot_state_t;

typedef enum protocol_budget_job_state_t {
  PROTOCOL_BUDGET_JOB_UNUSED = 0,
  PROTOCOL_BUDGET_JOB_WAITING,
  PROTOCOL_BUDGET_JOB_RUNNING
} protocol_budget_job_state_t;

typedef enum protocol_budget_work_t {
  PROTOCOL_BUDGET_SIGNATURE = 1,
  PROTOCOL_BUDGET_HPKE,
  PROTOCOL_BUDGET_NATIVE_SETUP
} protocol_budget_work_t;

/* Caller-owned objects; zero slots/jobs initially. One event loop or one lock
 * must serialize all calls. Use one owner shared across all relay circuits,
 * peers and service identities. Do not copy/reinitialize live budget objects.
 * Time is nonwrapping monotonic milliseconds. No API allocates or runs crypto.
 * Retain each returned generation with callbacks; stale generations cannot
 * release a reused handle. Handles remain bound to their original owner.
 * Caller must free buffers before acknowledging release; no callback may use
 * freed/reused memory, even when the generation can reject its stale result.
 * The owner outlives all handles and actual workers. The fixed budget owner
 * itself must be charged once as baseline process arena memory. */
struct protocol_budget_t {
  protocol_budget_limits_t limits;
  uint64_t last_ms;
  uint64_t crypto_credit_milli;
  uint64_t attempts_started;
  uint64_t last_generation;
  uint32_t slots;
  uint32_t arena_used;
  uint32_t memory_reservations;
  uint32_t running;
  uint32_t waiting;
  protocol_budget_job_t *head;
  protocol_budget_job_t *tail;
  bool initialized;
};

/* Non-slot shared backing allocations (map capacity, timer arrays, etc.).
 * Charge these separately rather than hiding unallocated capacity in payload
 * lengths. The handle cost itself also counts against the arena. */
struct protocol_budget_memory_t {
  protocol_budget_t *owner;
  uint64_t generation;
  uint32_t allocation_bytes;
  bool active;
};

struct protocol_budget_slot_t {
  protocol_budget_t *owner;
  uint64_t expires_ms;
  uint64_t generation;
  uint32_t allocation_bytes;
  uint32_t job_bytes;
  uint32_t jobs;
  protocol_budget_slot_state_t state;
  bool native_only;
};

struct protocol_budget_job_t {
  protocol_budget_t *issuer;
  protocol_budget_slot_t *slot;
  protocol_budget_job_t *previous;
  protocol_budget_job_t *next;
  uint64_t submitted_ms;
  uint64_t generation;
  uint32_t allocation_bytes;
  protocol_budget_job_state_t state;
  protocol_budget_work_t work;
};

void protocol_budget_default_limits(protocol_budget_limits_t *limits);
/* A smaller local ceiling causes refusal; it never changes accepted peer
 * profiles/deadlines. All limits must be positive and <= profile candidates.
 * On invalid configuration the owner is untouched. NULL limits uses defaults. */
protocol_budget_result_t protocol_budget_init(protocol_budget_t *owner,
    const protocol_budget_limits_t *limits, uint64_t now_ms);
/* Reserve shared backing capacity before allocation. This cannot create a
 * protocol slot or authorize any work. All allocations share the same arena.
 * Release only after the backing allocation is no longer used by any slot. */
protocol_budget_result_t protocol_budget_memory_reserve(protocol_budget_t *owner,
    protocol_budget_memory_t *memory, uint32_t allocation_bytes,
    uint64_t now_ms);
protocol_budget_result_t protocol_budget_memory_release(
    protocol_budget_memory_t *memory, uint64_t generation, uint64_t now_ms);
/* Reserve before allocating buffers/map/timer storage. allocation_bytes must
 * include the slot handle itself, allocated capacity and all object overhead.
 * Jobs reserve their own costs separately; do not count them in this base cost.
 * expires_ms is the ORIGINAL protocol deadline; caller validates the relevant
 * protocol lifetime. This API cannot extend it or grant a new retry window. */
protocol_budget_result_t protocol_budget_slot_reserve(protocol_budget_t *owner,
    protocol_budget_slot_t *slot, uint32_t allocation_bytes,
    uint64_t expires_ms, uint64_t now_ms);
/* Native Tor setup carries no financial replay authority. These slots share
 * the same count/arena ceilings but accept only NATIVE_SETUP work. Retire after
 * all real jobs end, without waiting for the setup deadline. Other slots can
 * never use early retirement. Cancellation cannot retire a RUNNING worker. */
protocol_budget_result_t protocol_budget_native_slot_reserve(
    protocol_budget_t *owner, protocol_budget_slot_t *slot,
    uint32_t allocation_bytes, uint64_t expires_ms, uint64_t now_ms);
protocol_budget_result_t protocol_budget_native_slot_retire(
    protocol_budget_slot_t *slot, uint64_t generation, uint64_t now_ms);
/* Terminal slots retain count and memory until original expiry. Shrink to
 * actual retained tombstone allocation only after freeing payload storage.
 * No active job may refer to the slot at terminal transition. */
protocol_budget_result_t protocol_budget_slot_finish(protocol_budget_slot_t *slot,
    uint64_t generation, uint32_t tombstone_bytes, uint64_t now_ms);
/* Release only after original expiry AND all jobs have completed/cancelled.
 * Repeated release is harmless. No release refills attempted-work credit. */
protocol_budget_result_t protocol_budget_slot_expire(protocol_budget_slot_t *slot,
    uint64_t generation, uint64_t now_ms);
/* One job is ONE attempted public-key primitive, including failed attempts.
 * Two request-key trials require two jobs. Native setup may share this ceiling
 * in addition to inherited Tor CPU-worker/onionskin/DoS limits, never instead.
 * Job cost includes sizeof(job), request buffers, queue/timer metadata and any
 * other incremental allocation. It counts against both slot and shared arena.
 * Queuing never extends the slot's original deadline. */
protocol_budget_result_t protocol_budget_submit(protocol_budget_slot_t *slot,
    uint64_t slot_generation, protocol_budget_job_t *job, protocol_budget_work_t work,
    uint32_t allocation_bytes, uint64_t now_ms);
/* Strict FIFO. Returns one RUNNING job on OK, or the still-reserved head on
 * EXPIRED. Dispose of its buffers and cancel it before starting the next job.
 * WAIT returns NULL. Drain expired jobs in a bounded event-loop turn; no
 * callback/thread is spawned.
 * Attempt credit is charged immediately before handing out a RUNNING job. */
protocol_budget_result_t protocol_budget_start_next(protocol_budget_t *owner,
    uint64_t now_ms, protocol_budget_job_t **job_out);
/* Earliest useful delay for one shared event-loop timer. Completion also wakes
 * the dispatcher when concurrency was full. Returns WAIT if the queue is empty;
 * otherwise OK with zero for immediately runnable/expired work. */
protocol_budget_result_t protocol_budget_next_wakeup(protocol_budget_t *owner,
    uint64_t now_ms, uint64_t *delay_ms);
/* Cancel WAITING work only. RUNNING work must complete; it still owns memory
 * and concurrency until the actual primitive ends. Release is idempotent. */
protocol_budget_result_t protocol_budget_cancel(protocol_budget_job_t *job,
    uint64_t generation, uint64_t now_ms);
/* Release running resources irrespective of success; never refund attempts.
 * EXPIRED means discard the result. Clock errors leave reservations intact. */
protocol_budget_result_t protocol_budget_complete(protocol_budget_job_t *job,
    uint64_t generation, uint64_t now_ms);

#endif /* !defined(TOR_PROTOCOL_BUDGET_H) */
