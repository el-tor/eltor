/* Copyright (c) 2026, The El Tor Project. */
/* See LICENSE for licensing information. */
#include "orconfig.h"
#include "feature/payment/payment_resources.h"
#include "lib/time/compat_time.h"
#include "lib/string/printf.h"
#include <stdbool.h>
#include <inttypes.h>
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


void
payment_resources_snapshot(payment_resource_snapshot_t *out)
{
  if (!out) return;
  memset(out, 0, sizeof(*out));
  out->initialized = resources.initialized;
  out->exhausted = resources.exhausted;
  if (resources.initialized) {
    out->free_limits = resources.free.limits;
    out->protocol_limits = resources.protocol.limits;
  } else if (resources.configured) {
    out->free_limits = resources.free_limits;
    out->protocol_limits = resources.limits;
  } else {
    free_capacity_default_limits(&out->free_limits);
    protocol_budget_default_limits(&out->protocol_limits);
  }
  out->received_bytes = resources.free.received_bytes;
  out->sent_bytes = resources.free.sent_bytes;
  out->attempts_started = resources.protocol.attempts_started;
  out->admission_credit_milli = resources.free.admissions.credit_milli;
  out->byte_credit_milli = resources.free.bytes.credit_milli;
  out->crypto_credit_milli = resources.protocol.crypto_credit_milli;
  out->live_circuits = resources.free.live_circuits;
  out->queued_bytes = resources.free.queued_bytes;
  out->slots = resources.protocol.slots;
  out->arena_used = resources.protocol.arena_used;
  out->reservations = resources.protocol.memory_reservations;
  out->running = resources.protocol.running;
  out->waiting = resources.protocol.waiting;
  out->operations = resources.operations;
}

char *
payment_resources_format_snapshot(const payment_resource_snapshot_t *s)
{
  if (!s) return NULL;
  char *answer;
  tor_asprintf(&answer,
    "FORMAT 1\nSTATE %u %u\nFREE %u %u %u %u\n"
    "LINK_BYTES %"PRIu64" %"PRIu64"\n"
    "ADMISSION %"PRIu64" %u %u %u %u\n"
    "TRAFFIC %"PRIu64" %u %u %u %u\n"
    "PROTOCOL %u %u %u %u %u\n"
    "WORK %u %u %u %u %"PRIu64" %"PRIu64" %u %u\n"
    "OPERATIONS %u %u",
    (unsigned)s->initialized, (unsigned)s->exhausted,
    s->live_circuits, s->free_limits.max_circuits,
    s->queued_bytes, s->free_limits.queue_bytes,
    s->received_bytes, s->sent_bytes, s->admission_credit_milli,
    s->free_limits.admission_rate, s->free_limits.admission_burst,
    s->free_limits.conn_admission_rate, s->free_limits.conn_admission_burst,
    s->byte_credit_milli, s->free_limits.byte_rate, s->free_limits.byte_burst,
    s->free_limits.conn_byte_rate, s->free_limits.conn_byte_burst,
    s->slots, s->protocol_limits.max_slots, s->arena_used,
    s->protocol_limits.arena_bytes, s->reservations,
    s->running, s->protocol_limits.max_running,
    s->waiting, s->protocol_limits.max_waiting,
    s->attempts_started, s->crypto_credit_milli,
    s->protocol_limits.crypto_rate, s->protocol_limits.crypto_burst,
    s->operations, PAYMENT_RESOURCES_OPERATIONS);
  return answer;
}
