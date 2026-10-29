/* Copyright (c) 2026, The El Tor Project. */
/* See LICENSE for licensing information. */
#include "orconfig.h"
#include "feature/payment/payment_resources.h"
#include "lib/time/compat_time.h"
#include <stdbool.h>
#include <string.h>

static struct {
  free_capacity_t free;
  protocol_budget_t protocol;
  protocol_budget_limits_t limits;
  free_capacity_limits_t free_limits;
  protocol_budget_memory_t baseline;
  bool initialized, configured, exhausted;
  uint32_t operations;
} resources;

static void
initialize(void)
{
  uint64_t now_ms;
  if (resources.initialized)
    return;
  now_ms = monotime_absolute_msec();
  (void)free_capacity_init_limits(&resources.free,
      resources.configured ? &resources.free_limits : NULL, now_ms);
  /* configure() validates a copied profile before accepting it. */
  (void)protocol_budget_init(&resources.protocol,
      resources.configured ? &resources.limits : NULL, now_ms);
  resources.initialized = true;
  /* Includes this receipt and all embedded fixed owner structures exactly once.
   * A lower operator ceiling unable to hold the fixed owner fails closed. */
  resources.exhausted = protocol_budget_memory_reserve(&resources.protocol,
      &resources.baseline, sizeof(resources), now_ms) != PROTOCOL_BUDGET_OK;
}

free_capacity_t *
payment_resources_free(void)
{
  initialize();
  return &resources.free;
}

protocol_budget_t *
payment_resources_protocol(void)
{
  initialize();
  return &resources.protocol;
}

protocol_budget_result_t
payment_resources_reserve(protocol_budget_memory_t *reservation, size_t bytes)
{
  if (bytes > UINT32_MAX)
    return PROTOCOL_BUDGET_REFUSE;
  protocol_budget_t *owner = payment_resources_protocol();
  if (resources.exhausted) return PROTOCOL_BUDGET_REFUSE;
  return protocol_budget_memory_reserve(owner, reservation, (uint32_t)bytes,
                                         monotime_absolute_msec());
}

protocol_budget_result_t
payment_resources_release(protocol_budget_memory_t *reservation)
{
  if (!reservation)
    return PROTOCOL_BUDGET_BAD_STATE;
  if (!reservation->active)
    return PROTOCOL_BUDGET_OK;
  uint64_t now_ms = monotime_absolute_msec();
  /* Cleanup grants no attempted-work credit on a clock rollback. Keep new
   * admissions fail-closed against the retained clock, but do not lose the
   * receipt for memory the caller has actually freed. */
  if (reservation->owner && now_ms < reservation->owner->last_ms)
    now_ms = reservation->owner->last_ms;
  return protocol_budget_memory_release(reservation, reservation->generation,
                                         now_ms);
}

bool
payment_resources_operation_reserve(bool *held)
{
  if (!held)
    return false;
  if (*held)
    return true;
  initialize();
  if (resources.exhausted ||
      resources.protocol.slots >= resources.protocol.limits.max_slots)
    return false;
  ++resources.operations;
  ++resources.protocol.slots;
  *held = true;
  return true;
}

void
payment_resources_operation_release(bool *held)
{
  if (held && *held) {
    --resources.operations;
    --resources.protocol.slots;
    *held = false;
  }
}

uint32_t
payment_resources_operations_used(void)
{
  return resources.operations;
}

int
payment_resources_configure(const protocol_budget_limits_t *limits)
{
  protocol_budget_t validation;
  if (resources.initialized || !limits ||
      protocol_budget_init(&validation, limits, 0) != PROTOCOL_BUDGET_OK)
    return -1;
  resources.limits = *limits;
  free_capacity_default_limits(&resources.free_limits);
  resources.configured = true;
  return 0;
}

int
payment_resources_configure_limits(const free_capacity_limits_t *free_limits,
    const protocol_budget_limits_t *protocol_limits)
{
  free_capacity_t free_validation;
  protocol_budget_t protocol_validation;
  if (!free_limits || !protocol_limits ||
      free_capacity_init_limits(&free_validation, free_limits, 0) < 0 ||
      protocol_budget_init(&protocol_validation, protocol_limits, 0) !=
        PROTOCOL_BUDGET_OK) return -1;
  const free_capacity_limits_t *old_free = resources.initialized ?
      &resources.free.limits : &resources.free_limits;
  const protocol_budget_limits_t *old_protocol = resources.initialized ?
      &resources.protocol.limits : &resources.limits;
  if (resources.initialized || resources.configured)
    return memcmp(old_free, free_limits, sizeof(*free_limits)) ||
           memcmp(old_protocol, protocol_limits, sizeof(*protocol_limits)) ?
           -1 : 0;
  resources.free_limits = *free_limits;
  resources.limits = *protocol_limits;
  resources.configured = true;
  return 0;
}

int
payment_resources_free_all(void)
{
  if (resources.initialized &&
      (resources.operations || resources.free.live_circuits ||
       resources.free.queued_bytes ||
       resources.protocol.arena_used !=
          (resources.baseline.active ? sizeof(resources) : 0) ||
       resources.protocol.slots ||
       resources.protocol.waiting || resources.protocol.running))
    return -1;
  (void)payment_resources_release(&resources.baseline);
  memset(&resources, 0, sizeof(resources));
  return 0;
}
