/* See LICENSE for licensing information. */
#include "orconfig.h"
#include "core/or/or.h"
#include "feature/payment/payment_schedule.h"
#include "test/test.h"

static payment_profile_policy_t
policy(void)
{
  payment_profile_policy_t p = {0};
  p.grace_ms = 15000;
  p.max_age_ms = 1800000;
  p.max_periods = 3;
  p.setup_timeout_ms = 30000;
  return p;
}

static void
test_schedule_activation(void *arg)
{
  payment_schedule_t s;
  payment_profile_policy_t p = policy();
  (void)arg;
  tt_int_op(payment_schedule_init(&s, &p, 1000), OP_EQ, 0);
  tt_int_op(payment_schedule_start(&s, 1000), OP_EQ, -1);
  tt_int_op(payment_schedule_commit(&s, 2000), OP_EQ, 0);
  tt_int_op(payment_schedule_start(&s, 3000), OP_EQ, 0);
  tt_int_op(payment_schedule_authorize(&s, 1, 4000), OP_EQ, 0);
  tt_assert(!s.started);
  tt_int_op(payment_schedule_authorize(&s, 0, 5000), OP_EQ, 0);
  tt_assert(s.started);
  tt_u64_op(s.t0_ms, OP_EQ, 5000);
  payment_schedule_tick(&s, 65000);
  tt_int_op(s.phase, OP_EQ, PAYMENT_SCHEDULE_GRACE);
  tt_int_op(payment_schedule_authorize(&s, 2, 70000), OP_EQ, 0);
  tt_int_op(s.phase, OP_EQ, PAYMENT_SCHEDULE_ACTIVE);
  tt_u64_op(s.t0_ms, OP_EQ, 5000);
  payment_schedule_tick(&s, 140000);
  tt_int_op(s.phase, OP_EQ, PAYMENT_SCHEDULE_EXPIRED);
  tt_int_op(payment_schedule_authorize(&s, 3, 140000), OP_EQ, -1);
 done: ;
}

static void
test_schedule_renewal(void *arg)
{
  payment_schedule_t s;
  payment_profile_policy_t p = policy();
  uint64_t r;
  (void)arg;
  tt_int_op(payment_schedule_init(&s, &p, 0), OP_EQ, 0);
  tt_int_op(payment_schedule_commit(&s, 0), OP_EQ, 0);
  tt_int_op(payment_schedule_authorize(&s, 0, 0), OP_EQ, 0);
  tt_int_op(payment_schedule_authorize(&s, 1, 0), OP_EQ, 0);
  tt_int_op(payment_schedule_start(&s, 0), OP_EQ, 0);
  for (r = 2; r <= 21; ++r) {
    uint64_t now = (r - 2) * 60000;
    if (r == 8 || r == 18)
      tt_int_op(payment_schedule_admit_next(&s, r / 10 + 1, now),
                OP_EQ, 0);
    tt_int_op(payment_schedule_authorize(&s, r, now), OP_EQ, 0);
    payment_schedule_tick(&s, now + 60000);
    tt_int_op(s.phase, OP_EQ, PAYMENT_SCHEDULE_ACTIVE);
    tt_u64_op(s.current_round, OP_EQ, r);
  }
  tt_u64_op(s.active_period, OP_EQ, 2);
  tt_u64_op(s.t0_ms, OP_EQ, 0);
  tt_int_op(payment_schedule_admit_next(&s, 3, 1200000), OP_EQ, -1);
 done: ;
}

static void
test_schedule_expiry(void *arg)
{
  payment_schedule_t s;
  payment_profile_policy_t p = policy();
  (void)arg;
  tt_int_op(payment_schedule_init(&s, &p, 0), OP_EQ, 0);
  tt_int_op(payment_schedule_commit(&s, 29000), OP_EQ, 0);
  payment_schedule_tick(&s, 30000);
  tt_int_op(s.phase, OP_EQ, PAYMENT_SCHEDULE_EXPIRED);
  tt_int_op(payment_schedule_init(&s, &p, 0), OP_EQ, 0);
  tt_int_op(payment_schedule_commit(&s, 0), OP_EQ, 0);
  tt_int_op(payment_schedule_authorize(&s, 0, 0), OP_EQ, 0);
  tt_int_op(payment_schedule_authorize(&s, 1, 0), OP_EQ, 0);
  tt_int_op(payment_schedule_start(&s, 0), OP_EQ, 0);
  /* Round three is prepaid during round two's grace; missing round two
   * must still terminate even if the timer jumps straight to round three. */
  tt_int_op(payment_schedule_authorize(&s, 3, 60000), OP_EQ, 0);
  payment_schedule_tick(&s, 120000);
  tt_int_op(s.phase, OP_EQ, PAYMENT_SCHEDULE_EXPIRED);
 done: ;
}

static void
test_schedule_limits(void *arg)
{
  payment_schedule_t s;
  payment_profile_policy_t p = policy();
  uint64_t r;
  (void)arg;
  p.max_age_ms = 1199999;
  tt_int_op(payment_schedule_init(&s, &p, 0), OP_EQ, 0);
  tt_int_op(payment_schedule_commit(&s, 0), OP_EQ, 0);
  tt_int_op(payment_schedule_authorize(&s, 0, 0), OP_EQ, 0);
  tt_int_op(payment_schedule_authorize(&s, 1, 0), OP_EQ, 0);
  tt_int_op(payment_schedule_start(&s, 0), OP_EQ, 0);
  /* Even though period one starts before max_age, its full allocation
   * would overrun it. No partial allocation may be admitted. */
  tt_int_op(payment_schedule_admit_next(&s, 1, 0), OP_EQ, -1);
  for (r = 2; r <= 10; ++r) {
    uint64_t now = (r - 2) * 60000;
    tt_int_op(payment_schedule_authorize(&s, r, now), OP_EQ, 0);
    payment_schedule_tick(&s, now + 60000);
  }
  tt_int_op(payment_schedule_admit_next(&s, 1, 540000), OP_EQ, -1);
  payment_schedule_tick(&s, 600000);
  tt_int_op(s.phase, OP_EQ, PAYMENT_SCHEDULE_EXPIRED);
  p = policy();
  tt_int_op(payment_schedule_init(&s, &p, 100), OP_EQ, 0);
  payment_schedule_tick(&s, 99);
  tt_int_op(s.phase, OP_EQ, PAYMENT_SCHEDULE_CLOSED);
  tt_int_op(payment_schedule_commit(&s, 100), OP_EQ, -1);
 done: ;
}

struct testcase_t payment_schedule_tests[] = {
  { "activation", test_schedule_activation, 0, NULL, NULL },
  { "renewal", test_schedule_renewal, 0, NULL, NULL },
  { "expiry", test_schedule_expiry, 0, NULL, NULL },
  { "limits", test_schedule_limits, 0, NULL, NULL },
  END_OF_TESTCASES
};
