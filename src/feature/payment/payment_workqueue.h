/* Copyright (c) 2026, The El Tor Project. */
/* See LICENSE for licensing information. */
#ifndef TOR_PAYMENT_WORKQUEUE_H
#define TOR_PAYMENT_WORKQUEUE_H
#include "feature/payment/protocol_budget.h"
#include <stddef.h>
typedef struct payment_work_t payment_work_t;
typedef int (*payment_work_start_fn)(payment_work_t *, void *);
typedef void (*payment_work_drop_fn)(void *);
/* Main-loop-owned shared dispatcher. Use this dispatcher for every live public
 * key job on payment_resources_protocol(); raw unregistered jobs cannot execute.
 * NULL slot creates a native-only ephemeral slot. Other work uses the caller's
 * retained financial slot. The caller's retained_bytes includes all native job,
 * request/reply buffers and copied worker metadata at their actual capacity.
 * Reserve BEFORE allocating caller buffers; attach arg before queueing. A
 * separate memory lease conservatively covers buffers through actual teardown,
 * including the interval between budget completion and freeing job metadata. */
payment_work_t *payment_work_reserve(protocol_budget_slot_t *slot,
    protocol_budget_work_t kind, size_t retained_bytes, uint64_t deadline_ms);
int payment_work_queue(payment_work_t *, payment_work_start_fn,
                        payment_work_drop_fn, void *arg);
/* Waiting cancellation invokes drop, which frees caller buffers. Running work
 * cannot be cancelled: its actual reply owns completion and stale-result drop. */
bool payment_work_cancel(payment_work_t *);
bool payment_work_result_timely(const payment_work_t *);
/* Call after actual worker completion and after freeing caller buffers. Return
 * false on expired/rollback result; it must never be installed into a circuit.
 * This releases running capacity, native slot and memory exactly once. */
bool payment_work_complete(payment_work_t *);
/* Unqueued reservation failure only, after any caller buffer has been freed. */
void payment_work_release(payment_work_t *);
void payment_work_dispatch(void);
int payment_workqueue_free_all(void);
#endif
