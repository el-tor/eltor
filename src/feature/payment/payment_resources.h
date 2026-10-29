/* Copyright (c) 2026, The El Tor Project. */
/* See LICENSE for licensing information. */
#ifndef TOR_PAYMENT_RESOURCES_H
#define TOR_PAYMENT_RESOURCES_H
#include "feature/payment/free_capacity.h"
#include "feature/payment/protocol_budget.h"
#include <stddef.h>
#define PAYMENT_RESOURCES_OPERATIONS 4096u

/* One relay-process owner, shared across circuits, connections, controllers and
 * service identities. Accessors initialize once; never refill on a new peer,
 * negotiation, renewal, config reload, daemon reconnect or paid activation. */
free_capacity_t *payment_resources_free(void);
protocol_budget_t *payment_resources_protocol(void);
/* Memory-only adapters use the process monotonic clock, independently of a
 * caller's protocol/test schedule. Reserve actual allocation capacity before
 * allocation; release only after use ends, under the same main-loop ownership. */
protocol_budget_result_t payment_resources_reserve(
    protocol_budget_memory_t *reservation, size_t allocation_bytes);
protocol_budget_result_t payment_resources_release(
    protocol_budget_memory_t *reservation);
/* Active/pending protocol operations share one process cap across origin and
 * relay roles. The caller retains held until actual retirement/teardown. */
bool payment_resources_operation_reserve(bool *held);
void payment_resources_operation_release(bool *held);
uint32_t payment_resources_operations_used(void);
/* Configure smaller protocol ceilings before the first owner initialization.
 * Returns -1 after initialization or for any invalid/enlarged profile value. */
int payment_resources_configure(const protocol_budget_limits_t *limits);
/* Process shutdown only, after all circuit/control reservations are released.
 * Refuse to reset live resources. Return -1 if a caller still owns anything. */
int payment_resources_free_all(void);
#endif /* !defined(TOR_PAYMENT_RESOURCES_H) */
