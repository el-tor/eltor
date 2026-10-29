/* Copyright (c) 2026, The El Tor Project. */
/* See LICENSE for licensing information. */
#include "orconfig.h"
#include "feature/payment/protocol_budget.h"
#include <string.h>

void
protocol_budget_default_limits(protocol_budget_limits_t *l)
{
  l->max_slots = PROTOCOL_BUDGET_SLOTS;
  l->max_slot_bytes = PROTOCOL_BUDGET_SLOT_BYTES;
  l->arena_bytes = PROTOCOL_BUDGET_ARENA_BYTES;
  l->crypto_rate = PROTOCOL_BUDGET_CRYPTO_RATE;
  l->crypto_burst = PROTOCOL_BUDGET_CRYPTO_BURST;
  l->max_running = PROTOCOL_BUDGET_RUNNING;
  l->max_waiting = PROTOCOL_BUDGET_WAITING;
  l->max_wait_ms = PROTOCOL_BUDGET_WAIT_MS;
}

static bool
limits_valid(const protocol_budget_limits_t *l)
{
#define WITHIN(field, ceiling) (l->field > 0 && l->field <= (ceiling))
  return WITHIN(max_slots, PROTOCOL_BUDGET_SLOTS) &&
    WITHIN(max_slot_bytes, PROTOCOL_BUDGET_SLOT_BYTES) &&
    l->max_slot_bytes >= sizeof(protocol_budget_slot_t) &&
    WITHIN(arena_bytes, PROTOCOL_BUDGET_ARENA_BYTES) &&
    l->arena_bytes >= sizeof(protocol_budget_slot_t) &&
    WITHIN(crypto_rate, PROTOCOL_BUDGET_CRYPTO_RATE) &&
    WITHIN(crypto_burst, PROTOCOL_BUDGET_CRYPTO_BURST) &&
    WITHIN(max_running, PROTOCOL_BUDGET_RUNNING) &&
    WITHIN(max_waiting, PROTOCOL_BUDGET_WAITING) &&
    WITHIN(max_wait_ms, PROTOCOL_BUDGET_WAIT_MS);
#undef WITHIN
}

protocol_budget_result_t
protocol_budget_init(protocol_budget_t *owner,
                     const protocol_budget_limits_t *limits, uint64_t now_ms)
{
  protocol_budget_limits_t defaults, accepted;
  if (!owner)
    return PROTOCOL_BUDGET_BAD_STATE;
  if (!limits) {
    protocol_budget_default_limits(&defaults);
    limits = &defaults;
  }
  if (!limits_valid(limits))
    return PROTOCOL_BUDGET_BAD_STATE;
  accepted = *limits;
  memset(owner, 0, sizeof(*owner));
  owner->limits = accepted;
  owner->last_ms = now_ms;
  owner->crypto_credit_milli = (uint64_t)accepted.crypto_burst * 1000;
  owner->initialized = true;
  return PROTOCOL_BUDGET_OK;
}

static protocol_budget_result_t
advance(protocol_budget_t *owner, uint64_t now_ms)
{
  uint64_t elapsed, gap;
  if (!owner || !owner->initialized)
    return PROTOCOL_BUDGET_BAD_STATE;
  if (now_ms < owner->last_ms)
    return PROTOCOL_BUDGET_CLOCK_ERROR;
  elapsed = now_ms - owner->last_ms;
  gap = (uint64_t)owner->limits.crypto_burst * 1000 -
        owner->crypto_credit_milli;
  if (elapsed > gap / owner->limits.crypto_rate)
    owner->crypto_credit_milli = (uint64_t)owner->limits.crypto_burst * 1000;
  else
    owner->crypto_credit_milli += elapsed * owner->limits.crypto_rate;
  owner->last_ms = now_ms;
  return PROTOCOL_BUDGET_OK;
}

protocol_budget_result_t
protocol_budget_memory_reserve(protocol_budget_t *owner,
    protocol_budget_memory_t *memory, uint32_t bytes, uint64_t now_ms)
{
  protocol_budget_result_t r;
  if (!memory || memory->active || bytes < sizeof(*memory) ||
      (memory->owner && memory->owner != owner))
    return PROTOCOL_BUDGET_BAD_STATE;
  r = advance(owner, now_ms);
  if (r != PROTOCOL_BUDGET_OK)
    return r;
  if (owner->last_generation == UINT64_MAX ||
      bytes > owner->limits.arena_bytes - owner->arena_used)
    return PROTOCOL_BUDGET_REFUSE;
  memory->owner = owner;
  memory->generation = ++owner->last_generation;
  memory->allocation_bytes = bytes;
  memory->active = true;
  owner->arena_used += bytes;
  ++owner->memory_reservations;
  return PROTOCOL_BUDGET_OK;
}

protocol_budget_result_t
protocol_budget_memory_release(protocol_budget_memory_t *memory,
    uint64_t generation, uint64_t now_ms)
{
  protocol_budget_result_t r;
  if (!memory || !generation || memory->generation != generation)
    return PROTOCOL_BUDGET_BAD_STATE;
  if (!memory->active)
    return PROTOCOL_BUDGET_OK;
  r = advance(memory->owner, now_ms);
  if (r != PROTOCOL_BUDGET_OK)
    return r;
  memory->owner->arena_used -= memory->allocation_bytes;
  --memory->owner->memory_reservations;
  memory->active = false;
  memory->allocation_bytes = 0;
  return PROTOCOL_BUDGET_OK;
}

protocol_budget_result_t
protocol_budget_slot_reserve(protocol_budget_t *owner,
    protocol_budget_slot_t *slot, uint32_t bytes,
    uint64_t expires_ms, uint64_t now_ms)
{
  protocol_budget_result_t r;
  if (!slot || slot->state != PROTOCOL_BUDGET_SLOT_UNUSED ||
      (slot->owner && slot->owner != owner) || bytes < sizeof(*slot))
    return PROTOCOL_BUDGET_BAD_STATE;
  r = advance(owner, now_ms);
  if (r != PROTOCOL_BUDGET_OK)
    return r;
  if (expires_ms <= now_ms)
    return PROTOCOL_BUDGET_EXPIRED;
  if (owner->last_generation == UINT64_MAX ||
      owner->slots >= owner->limits.max_slots ||
      bytes > owner->limits.max_slot_bytes ||
      bytes > owner->limits.arena_bytes - owner->arena_used)
    return PROTOCOL_BUDGET_REFUSE;
  memset(slot, 0, sizeof(*slot));
  slot->owner = owner;
  slot->generation = ++owner->last_generation;
  slot->state = PROTOCOL_BUDGET_SLOT_LIVE;
  slot->expires_ms = expires_ms;
  slot->allocation_bytes = bytes;
  owner->arena_used += bytes;
  ++owner->slots;
  return PROTOCOL_BUDGET_OK;
}

protocol_budget_result_t
protocol_budget_native_slot_reserve(protocol_budget_t *owner,
    protocol_budget_slot_t *slot, uint32_t bytes,
    uint64_t expires_ms, uint64_t now_ms)
{
  protocol_budget_result_t r = protocol_budget_slot_reserve(owner, slot, bytes,
                                                          expires_ms, now_ms);
  if (r == PROTOCOL_BUDGET_OK) slot->native_only = true;
  return r;
}

protocol_budget_result_t
protocol_budget_native_slot_retire(protocol_budget_slot_t *slot,
                                   uint64_t generation, uint64_t now_ms)
{
  if (!slot || !generation || slot->generation != generation ||
      !slot->native_only)
    return PROTOCOL_BUDGET_BAD_STATE;
  if (slot->state == PROTOCOL_BUDGET_SLOT_UNUSED)
    return PROTOCOL_BUDGET_OK;
  if (slot->jobs) return PROTOCOL_BUDGET_WAIT;
  protocol_budget_result_t r = advance(slot->owner, now_ms);
  if (r != PROTOCOL_BUDGET_OK) return r;
  slot->owner->arena_used -= slot->allocation_bytes;
  --slot->owner->slots;
  slot->allocation_bytes = 0;
  slot->state = PROTOCOL_BUDGET_SLOT_UNUSED;
  return PROTOCOL_BUDGET_OK;
}

protocol_budget_result_t
protocol_budget_slot_finish(protocol_budget_slot_t *slot, uint64_t generation,
                            uint32_t bytes, uint64_t now_ms)
{
  protocol_budget_result_t r;
  if (!slot || slot->generation != generation ||
      slot->state == PROTOCOL_BUDGET_SLOT_UNUSED ||
      bytes < sizeof(*slot) || bytes > slot->allocation_bytes || slot->jobs)
    return PROTOCOL_BUDGET_BAD_STATE;
  r = advance(slot->owner, now_ms);
  if (r != PROTOCOL_BUDGET_OK)
    return r;
  if (now_ms >= slot->expires_ms)
    return PROTOCOL_BUDGET_EXPIRED;
  slot->owner->arena_used -= slot->allocation_bytes - bytes;
  slot->allocation_bytes = bytes;
  slot->state = PROTOCOL_BUDGET_SLOT_TOMBSTONE;
  return PROTOCOL_BUDGET_OK;
}

protocol_budget_result_t
protocol_budget_slot_expire(protocol_budget_slot_t *slot, uint64_t generation,
                            uint64_t now_ms)
{
  protocol_budget_result_t r;
  if (!slot || !generation || slot->generation != generation)
    return PROTOCOL_BUDGET_BAD_STATE;
  if (slot->state == PROTOCOL_BUDGET_SLOT_UNUSED)
    return PROTOCOL_BUDGET_OK;
  r = advance(slot->owner, now_ms);
  if (r != PROTOCOL_BUDGET_OK)
    return r;
  if (now_ms < slot->expires_ms || slot->jobs)
    return PROTOCOL_BUDGET_WAIT;
  slot->owner->arena_used -= slot->allocation_bytes;
  --slot->owner->slots;
  slot->allocation_bytes = 0;
  slot->state = PROTOCOL_BUDGET_SLOT_UNUSED;
  return PROTOCOL_BUDGET_OK;
}

protocol_budget_result_t
protocol_budget_submit(protocol_budget_slot_t *slot, uint64_t slot_generation,
    protocol_budget_job_t *job, protocol_budget_work_t work,
    uint32_t bytes, uint64_t now_ms)
{
  protocol_budget_t *owner;
  protocol_budget_result_t r;
  if (!slot || slot->generation != slot_generation ||
      slot->state != PROTOCOL_BUDGET_SLOT_LIVE ||
      !job || job->state != PROTOCOL_BUDGET_JOB_UNUSED ||
      (job->issuer && job->issuer != slot->owner) ||
      bytes < sizeof(*job) || work < PROTOCOL_BUDGET_SIGNATURE ||
      work > PROTOCOL_BUDGET_NATIVE_SETUP ||
      (slot->native_only && work != PROTOCOL_BUDGET_NATIVE_SETUP))
    return PROTOCOL_BUDGET_BAD_STATE;
  owner = slot->owner;
  r = advance(owner, now_ms);
  if (r != PROTOCOL_BUDGET_OK)
    return r;
  if (now_ms >= slot->expires_ms)
    return PROTOCOL_BUDGET_EXPIRED;
  if (owner->last_generation == UINT64_MAX ||
      owner->waiting >= owner->limits.max_waiting ||
      bytes > owner->limits.max_slot_bytes - slot->allocation_bytes -
              slot->job_bytes ||
      bytes > owner->limits.arena_bytes - owner->arena_used)
    return PROTOCOL_BUDGET_REFUSE;
  memset(job, 0, sizeof(*job));
  job->slot = slot;
  job->issuer = owner;
  job->generation = ++owner->last_generation;
  job->state = PROTOCOL_BUDGET_JOB_WAITING;
  job->work = work;
  job->allocation_bytes = bytes;
  job->submitted_ms = now_ms;
  job->previous = owner->tail;
  if (owner->tail)
    owner->tail->next = job;
  else
    owner->head = job;
  owner->tail = job;
  ++owner->waiting;
  ++slot->jobs;
  slot->job_bytes += bytes;
  owner->arena_used += bytes;
  return PROTOCOL_BUDGET_OK;
}

static void
unlink_waiting(protocol_budget_t *owner, protocol_budget_job_t *job)
{
  if (job->previous)
    job->previous->next = job->next;
  else
    owner->head = job->next;
  if (job->next)
    job->next->previous = job->previous;
  else
    owner->tail = job->previous;
  --owner->waiting;
  job->previous = job->next = NULL;
}

static void
release_job(protocol_budget_job_t *job)
{
  protocol_budget_slot_t *slot = job->slot;
  slot->job_bytes -= job->allocation_bytes;
  slot->owner->arena_used -= job->allocation_bytes;
  --slot->jobs;
  job->slot = NULL;
  job->allocation_bytes = 0;
  job->state = PROTOCOL_BUDGET_JOB_UNUSED;
}

protocol_budget_result_t
protocol_budget_start_next(protocol_budget_t *owner, uint64_t now_ms,
                           protocol_budget_job_t **job_out)
{
  protocol_budget_job_t *job;
  protocol_budget_result_t r;
  if (!job_out)
    return PROTOCOL_BUDGET_BAD_STATE;
  *job_out = NULL;
  r = advance(owner, now_ms);
  if (r != PROTOCOL_BUDGET_OK)
    return r;
  job = owner->head;
  if (!job)
    return PROTOCOL_BUDGET_WAIT;
  if (now_ms >= job->slot->expires_ms ||
      now_ms - job->submitted_ms >= owner->limits.max_wait_ms) {
    /* Keep its reservation until the caller disposes of queued buffers and
     * acknowledges cancellation; admitting new memory earlier is unsafe. */
    *job_out = job;
    return PROTOCOL_BUDGET_EXPIRED;
  }
  if (owner->running >= owner->limits.max_running ||
      owner->crypto_credit_milli < 1000)
    return PROTOCOL_BUDGET_WAIT;
  unlink_waiting(owner, job);
  owner->crypto_credit_milli -= 1000;
  if (owner->attempts_started != UINT64_MAX)
    ++owner->attempts_started;
  ++owner->running;
  job->state = PROTOCOL_BUDGET_JOB_RUNNING;
  *job_out = job;
  return PROTOCOL_BUDGET_OK;
}

protocol_budget_result_t
protocol_budget_next_wakeup(protocol_budget_t *owner, uint64_t now_ms,
                            uint64_t *delay_ms)
{
  protocol_budget_job_t *job;
  protocol_budget_result_t r;
  uint64_t elapsed, delay, expiry_delay, credit_delay;
  if (!delay_ms)
    return PROTOCOL_BUDGET_BAD_STATE;
  *delay_ms = 0;
  r = advance(owner, now_ms);
  if (r != PROTOCOL_BUDGET_OK)
    return r;
  job = owner->head;
  if (!job)
    return PROTOCOL_BUDGET_WAIT;
  elapsed = now_ms - job->submitted_ms;
  delay = elapsed >= owner->limits.max_wait_ms ? 0 :
          owner->limits.max_wait_ms - elapsed;
  expiry_delay = now_ms >= job->slot->expires_ms ? 0 :
                 job->slot->expires_ms - now_ms;
  if (expiry_delay < delay)
    delay = expiry_delay;
  if (owner->running < owner->limits.max_running) {
    credit_delay = owner->crypto_credit_milli >= 1000 ? 0 :
      (1000 - owner->crypto_credit_milli + owner->limits.crypto_rate - 1) /
      owner->limits.crypto_rate;
    if (credit_delay < delay)
      delay = credit_delay;
  }
  *delay_ms = delay;
  return PROTOCOL_BUDGET_OK;
}

protocol_budget_result_t
protocol_budget_cancel(protocol_budget_job_t *job, uint64_t generation,
                       uint64_t now_ms)
{
  protocol_budget_result_t r;
  if (!job || !generation || job->generation != generation)
    return PROTOCOL_BUDGET_BAD_STATE;
  if (job->state == PROTOCOL_BUDGET_JOB_UNUSED)
    return PROTOCOL_BUDGET_OK;
  if (job->state != PROTOCOL_BUDGET_JOB_WAITING)
    return PROTOCOL_BUDGET_BAD_STATE;
  r = advance(job->slot->owner, now_ms);
  if (r != PROTOCOL_BUDGET_OK)
    return r;
  unlink_waiting(job->slot->owner, job);
  release_job(job);
  return PROTOCOL_BUDGET_OK;
}

protocol_budget_result_t
protocol_budget_complete(protocol_budget_job_t *job, uint64_t generation,
                         uint64_t now_ms)
{
  protocol_budget_result_t r;
  bool expired;
  if (!job || !generation || job->generation != generation)
    return PROTOCOL_BUDGET_BAD_STATE;
  if (job->state == PROTOCOL_BUDGET_JOB_UNUSED)
    return PROTOCOL_BUDGET_OK;
  if (job->state != PROTOCOL_BUDGET_JOB_RUNNING)
    return PROTOCOL_BUDGET_BAD_STATE;
  r = advance(job->slot->owner, now_ms);
  if (r != PROTOCOL_BUDGET_OK)
    return r;
  expired = now_ms >= job->slot->expires_ms;
  --job->slot->owner->running;
  release_job(job);
  return expired ? PROTOCOL_BUDGET_EXPIRED : PROTOCOL_BUDGET_OK;
}
