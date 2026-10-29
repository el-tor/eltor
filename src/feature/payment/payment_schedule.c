/* See LICENSE for licensing information. */
#include "orconfig.h"
#include "feature/payment/payment_schedule.h"
#include <string.h>

static bool
terminal(const payment_schedule_t *s)
{
  return s->phase == PAYMENT_SCHEDULE_CLOSED ||
         s->phase == PAYMENT_SCHEDULE_EXPIRED;
}

void
payment_schedule_close(payment_schedule_t *s)
{
  if (!terminal(s)) s->phase = PAYMENT_SCHEDULE_CLOSED;
}

int
payment_schedule_init(payment_schedule_t *s,
                      const payment_profile_policy_t *policy, uint64_t now_ms)
{
  uint8_t wire[PAYMENT_PROFILE_TERMS_LEN];
  if (!s || !policy ||
      payment_profile_policy_encode(wire, sizeof(wire), policy) != 0 ||
      policy->setup_timeout_ms > UINT64_MAX - now_ms ||
      policy->max_age_ms > UINT64_MAX - now_ms - policy->setup_timeout_ms)
    return -1;
  memset(s, 0, sizeof(*s));
  s->policy = *policy;
  s->constructed_ms = s->last_ms = now_ms;
  s->phase = PAYMENT_SCHEDULE_UNCOMMITTED;
  return 0;
}

void
payment_schedule_tick(payment_schedule_t *s, uint64_t now_ms)
{
  uint64_t elapsed, period, offset, scheduled, previous;
  if (terminal(s)) return;
  if (now_ms < s->last_ms) {
    payment_schedule_close(s);
    return;
  }
  s->last_ms = now_ms;
  if (!s->started) {
    if (now_ms - s->constructed_ms >= s->policy.setup_timeout_ms) {
      s->phase = PAYMENT_SCHEDULE_EXPIRED;
      return;
    }
    if (!s->committed) return;
    s->phase = s->start_requested ? PAYMENT_SCHEDULE_WAIT_PAYMENT :
                                  PAYMENT_SCHEDULE_COMMITTED;
    if (!(s->start_requested && s->fee_authorized &&
          (s->authorized & 1))) return;
    s->started = true;
    s->t0_ms = now_ms;
  }
  elapsed = now_ms - s->t0_ms;
  if (elapsed >= s->policy.max_age_ms) {
    s->phase = PAYMENT_SCHEDULE_EXPIRED;
    return;
  }
  scheduled = elapsed / PAYMENT_PROFILE_ROUND_MS + 1;
  /* A delayed timer must not skip an unfunded round merely because a later
   * round was prepaid. At most two ten-round allocations are retained. */
  if (scheduled - s->current_round > 20) {
    s->phase = PAYMENT_SCHEDULE_EXPIRED;
    return;
  }
  for (previous = s->current_round; previous && previous < scheduled;
       ++previous) {
    uint64_t old_period = (previous - 1) / 10;
    uint16_t mask = old_period == s->active_period ? s->authorized :
      (old_period == s->active_period + 1 && s->next_admitted ?
       s->next_authorized : 0);
    if (!(mask & (1u << ((previous - 1) % 10)))) {
      s->phase = PAYMENT_SCHEDULE_EXPIRED;
      return;
    }
  }
  s->current_round = scheduled;
  period = (s->current_round - 1) / PAYMENT_PROFILE_ID_COUNT;
  if (period >= s->policy.max_periods || period > s->active_period + 1) {
    s->phase = PAYMENT_SCHEDULE_EXPIRED;
    return;
  }
  if (period != s->active_period) {
    if (!s->next_admitted) {
      s->phase = PAYMENT_SCHEDULE_EXPIRED;
      return;
    }
    s->active_period = period;
    s->authorized = s->next_authorized;
    s->next_authorized = 0;
    s->next_admitted = false;
  }
  offset = (s->current_round - 1) % PAYMENT_PROFILE_ID_COUNT;
  if (s->authorized & (1u << offset)) {
    s->phase = PAYMENT_SCHEDULE_ACTIVE;
  } else if (elapsed % PAYMENT_PROFILE_ROUND_MS < s->policy.grace_ms) {
    s->phase = PAYMENT_SCHEDULE_GRACE;
  } else {
    s->phase = PAYMENT_SCHEDULE_EXPIRED;
  }
}

int
payment_schedule_commit(payment_schedule_t *s, uint64_t now_ms)
{
  payment_schedule_tick(s, now_ms);
  if (terminal(s)) return -1;
  s->committed = true;
  payment_schedule_tick(s, now_ms);
  return 0;
}

int
payment_schedule_start(payment_schedule_t *s, uint64_t now_ms)
{
  payment_schedule_tick(s, now_ms);
  if (terminal(s) || !s->committed) return -1;
  s->start_requested = true;
  payment_schedule_tick(s, now_ms);
  return 0;
}

int
payment_schedule_authorize(payment_schedule_t *s, uint64_t round,
                           uint64_t now_ms)
{
  uint64_t period, offset, start, elapsed;
  uint16_t *mask;
  payment_schedule_tick(s, now_ms);
  if (terminal(s) || !s->committed) return -1;
  if (round == 0) {
    s->fee_authorized = true;
    payment_schedule_tick(s, now_ms);
    return 0;
  }
  period = (round - 1) / PAYMENT_PROFILE_ID_COUNT;
  offset = (round - 1) % PAYMENT_PROFILE_ID_COUNT;
  if (period == s->active_period) mask = &s->authorized;
  else if (period == s->active_period + 1 && s->next_admitted)
    mask = &s->next_authorized;
  else return -1;
  if (*mask & (1u << offset)) return 0;
  if (!s->started) {
    if (round != 1) return -1;
  } else {
    if (round == 1 || round - 1 > UINT64_MAX / PAYMENT_PROFILE_ROUND_MS)
      return -1;
    start = (round - 1) * PAYMENT_PROFILE_ROUND_MS;
    elapsed = now_ms - s->t0_ms;
    if (elapsed < start - PAYMENT_PROFILE_ROUND_MS ||
        start > UINT64_MAX - s->policy.grace_ms ||
        elapsed >= start + s->policy.grace_ms)
      return -1;
  }
  *mask |= (uint16_t)(1u << offset);
  payment_schedule_tick(s, now_ms);
  return 0;
}

int
payment_schedule_admit_next(payment_schedule_t *s, uint64_t period,
                            uint64_t now_ms)
{
  uint64_t activation, elapsed;
  payment_schedule_tick(s, now_ms);
  if (terminal(s) || !s->started || period != s->active_period + 1 ||
      period >= s->policy.max_periods)
    return -1;
  if (s->next_admitted) return 0;
  if (period > UINT64_MAX / (10 * PAYMENT_PROFILE_ROUND_MS)) return -1;
  activation = period * (10 * PAYMENT_PROFILE_ROUND_MS);
  elapsed = now_ms - s->t0_ms;
  if (activation > UINT64_MAX - 10 * PAYMENT_PROFILE_ROUND_MS ||
      activation + 10 * PAYMENT_PROFILE_ROUND_MS > s->policy.max_age_ms ||
      elapsed >= activation - PAYMENT_PROFILE_ROUND_MS)
    return -1;
  s->next_admitted = true;
  return 0;
}
