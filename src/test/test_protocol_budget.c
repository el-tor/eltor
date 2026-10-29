/* Copyright (c) 2026, The El Tor Project. */
/* See LICENSE for licensing information. */
#include "orconfig.h"
#include "core/or/or.h"
#include "feature/payment/protocol_budget.h"
#include "test/test.h"

#define SLOT_BYTES 256u
#define JOB_BYTES 128u
#define SLOT_INIT(o, s, bytes, deadline, now) \
  protocol_budget_slot_reserve((o), (s), (bytes), (deadline), (now))
#define SUBMIT(s, j, kind, bytes, now) \
  protocol_budget_submit((s), (s)->generation, (j), (kind), (bytes), (now))
#define CANCEL(j, now) protocol_budget_cancel((j), (j)->generation, (now))
#define COMPLETE(j, now) protocol_budget_complete((j), (j)->generation, (now))
#define EXPIRE(s, now) protocol_budget_slot_expire((s), (s)->generation, (now))
#define FINISH(s, bytes, now) \
  protocol_budget_slot_finish((s), (s)->generation, (bytes), (now))

static void
test_protocol_budget_config(void *arg)
{
  protocol_budget_t owner, saved;
  protocol_budget_limits_t limits;
  (void)arg;
  protocol_budget_default_limits(&limits);
  tt_uint_op(limits.max_slots, OP_EQ, 4096);
  tt_uint_op(limits.max_slot_bytes, OP_EQ, 16384);
  tt_uint_op(limits.arena_bytes, OP_EQ, 64 * 1048576);
  tt_uint_op(limits.crypto_rate, OP_EQ, 256);
  tt_uint_op(limits.crypto_burst, OP_EQ, 512);
  tt_uint_op(limits.max_running, OP_EQ, 32);
  tt_uint_op(limits.max_waiting, OP_EQ, 128);
  tt_uint_op(limits.max_wait_ms, OP_EQ, 1000);
  tt_int_op(protocol_budget_init(&owner, NULL, 100), OP_EQ, PROTOCOL_BUDGET_OK);
  saved = owner;
#define INVALID(field, value) STMT_BEGIN { \
    protocol_budget_default_limits(&limits); \
    limits.field = (value); \
    tt_int_op(protocol_budget_init(&owner, &limits, 0), OP_EQ, \
              PROTOCOL_BUDGET_BAD_STATE); \
    tt_mem_op(&owner, OP_EQ, &saved, sizeof(owner)); \
  } STMT_END
  INVALID(max_slots, 4097);
  INVALID(max_slot_bytes, 16385);
  INVALID(arena_bytes, 64 * 1048576 + 1);
  INVALID(crypto_rate, 257);
  INVALID(crypto_burst, 513);
  INVALID(max_running, 33);
  INVALID(max_waiting, 129);
  INVALID(max_wait_ms, 1001);
  INVALID(crypto_rate, 0);
  INVALID(max_slot_bytes, sizeof(protocol_budget_slot_t) - 1);
#undef INVALID
  protocol_budget_default_limits(&limits);
  limits.max_slots = 2;
  limits.max_slot_bytes = 1024;
  limits.arena_bytes = 2048;
  limits.crypto_rate = 1;
  limits.crypto_burst = 1;
  limits.max_running = 1;
  limits.max_waiting = 1;
  limits.max_wait_ms = 100;
  tt_int_op(protocol_budget_init(&owner, &limits, 0), OP_EQ,
            PROTOCOL_BUDGET_OK);
  tt_mem_op(&owner.limits, OP_EQ, &limits, sizeof(limits));
 done:
  ;
}

static void
test_protocol_budget_slots(void *arg)
{
  protocol_budget_t owner;
  protocol_budget_limits_t limits;
  protocol_budget_slot_t slot[3] = {{0}};
  (void)arg;
  protocol_budget_default_limits(&limits);
  limits.max_slots = 2;
  limits.arena_bytes = 2 * SLOT_BYTES;
  tt_int_op(protocol_budget_init(&owner, &limits, 0), OP_EQ,
            PROTOCOL_BUDGET_OK);
  tt_int_op(SLOT_INIT(&owner, &slot[0], SLOT_BYTES, 30000, 0), OP_EQ,
            PROTOCOL_BUDGET_OK);
  tt_int_op(SLOT_INIT(&owner, &slot[1], SLOT_BYTES, 30000, 0), OP_EQ,
            PROTOCOL_BUDGET_OK);
  tt_int_op(SLOT_INIT(&owner, &slot[2], SLOT_BYTES, 30000, 0), OP_EQ,
            PROTOCOL_BUDGET_REFUSE);
  tt_int_op(FINISH(&slot[0], sizeof(slot[0]), 0), OP_EQ,
            PROTOCOL_BUDGET_OK);
  tt_uint_op(slot[0].state, OP_EQ, PROTOCOL_BUDGET_SLOT_TOMBSTONE);
  tt_u64_op(slot[0].expires_ms, OP_EQ, 30000);
  /* Shrinking memory cannot evade the live+tombstone slot count. */
  tt_int_op(SLOT_INIT(&owner, &slot[2], SLOT_BYTES, 30000, 0), OP_EQ,
            PROTOCOL_BUDGET_REFUSE);
  tt_uint_op(owner.slots, OP_EQ, 2);
  tt_uint_op(owner.arena_used, OP_EQ, SLOT_BYTES + sizeof(slot[0]));
  tt_int_op(EXPIRE(&slot[0], 29999), OP_EQ, PROTOCOL_BUDGET_WAIT);
  tt_int_op(EXPIRE(&slot[0], 30000), OP_EQ, PROTOCOL_BUDGET_OK);
  tt_int_op(EXPIRE(&slot[0], 30000), OP_EQ, PROTOCOL_BUDGET_OK);
  tt_uint_op(owner.slots, OP_EQ, 1);
  tt_uint_op(owner.arena_used, OP_EQ, SLOT_BYTES);
  tt_int_op(EXPIRE(&slot[1], 30000), OP_EQ, PROTOCOL_BUDGET_OK);
  tt_uint_op(owner.slots, OP_EQ, 0);
  tt_uint_op(owner.arena_used, OP_EQ, 0);
  tt_int_op(SLOT_INIT(&owner, &slot[2], UINT32_MAX, UINT64_MAX, 30000), OP_EQ,
            PROTOCOL_BUDGET_REFUSE);
  tt_int_op(SLOT_INIT(&owner, &slot[2], SLOT_BYTES, 30000, 30000), OP_EQ,
            PROTOCOL_BUDGET_EXPIRED);
 done:
  ;
}

static void
test_protocol_budget_full_arena(void *arg)
{
  protocol_budget_t owner;
  protocol_budget_slot_t *slot = NULL;
  (void)arg;
  tt_int_op(protocol_budget_init(&owner, NULL, 0), OP_EQ, PROTOCOL_BUDGET_OK);
  slot = tor_calloc(PROTOCOL_BUDGET_SLOTS + 1, sizeof(*slot));
  for (unsigned i = 0; i < PROTOCOL_BUDGET_SLOTS; ++i)
    tt_int_op(SLOT_INIT(&owner, &slot[i], PROTOCOL_BUDGET_SLOT_BYTES,
                       30000, 0), OP_EQ, PROTOCOL_BUDGET_OK);
  tt_uint_op(owner.arena_used, OP_EQ, 64 * 1048576);
  tt_int_op(SLOT_INIT(&owner, &slot[PROTOCOL_BUDGET_SLOTS],
                     sizeof(*slot), 30000, 0), OP_EQ, PROTOCOL_BUDGET_REFUSE);
  tt_int_op(FINISH(&slot[0], sizeof(*slot), 0), OP_EQ, PROTOCOL_BUDGET_OK);
  tt_int_op(SLOT_INIT(&owner, &slot[PROTOCOL_BUDGET_SLOTS],
                     sizeof(*slot), 30000, 0), OP_EQ, PROTOCOL_BUDGET_REFUSE);
  tt_uint_op(owner.slots, OP_EQ, 4096);
 done:
  tor_free(slot);
}

static void
test_protocol_budget_fifo_and_concurrency(void *arg)
{
  protocol_budget_t owner;
  protocol_budget_slot_t slot = {0};
  protocol_budget_job_t jobs[161] = {{0}}, *selected = NULL;
  uint64_t delay;
  (void)arg;
  tt_int_op(protocol_budget_init(&owner, NULL, 0), OP_EQ, PROTOCOL_BUDGET_OK);
  tt_int_op(SLOT_INIT(&owner, &slot, SLOT_BYTES, 30000, 0), OP_EQ,
            PROTOCOL_BUDGET_OK);
  for (unsigned i = 0; i < 32; ++i) {
    tt_int_op(SUBMIT(&slot, &jobs[i], PROTOCOL_BUDGET_SIGNATURE,
                     sizeof(jobs[i]), 0), OP_EQ, PROTOCOL_BUDGET_OK);
    tt_int_op(protocol_budget_start_next(&owner, 0, &selected), OP_EQ,
              PROTOCOL_BUDGET_OK);
    tt_ptr_op(selected, OP_EQ, &jobs[i]);
  }
  for (unsigned i = 32; i < 160; ++i)
    tt_int_op(SUBMIT(&slot, &jobs[i], PROTOCOL_BUDGET_HPKE,
                     sizeof(jobs[i]), 0), OP_EQ, PROTOCOL_BUDGET_OK);
  tt_int_op(SUBMIT(&slot, &jobs[160], PROTOCOL_BUDGET_NATIVE_SETUP,
                   sizeof(jobs[160]), 0), OP_EQ, PROTOCOL_BUDGET_REFUSE);
  tt_uint_op(owner.running, OP_EQ, 32);
  tt_uint_op(owner.waiting, OP_EQ, 128);
  tt_int_op(protocol_budget_next_wakeup(&owner, 0, &delay), OP_EQ,
            PROTOCOL_BUDGET_OK);
  tt_u64_op(delay, OP_EQ, 1000);
  tt_int_op(protocol_budget_start_next(&owner, 0, &selected), OP_EQ,
            PROTOCOL_BUDGET_WAIT);
  tt_ptr_op(selected, OP_EQ, NULL);
  tt_int_op(CANCEL(&jobs[0], 0), OP_EQ, PROTOCOL_BUDGET_BAD_STATE);
  tt_int_op(COMPLETE(&jobs[0], 0), OP_EQ, PROTOCOL_BUDGET_OK);
  tt_int_op(protocol_budget_start_next(&owner, 0, &selected), OP_EQ,
            PROTOCOL_BUDGET_OK);
  tt_ptr_op(selected, OP_EQ, &jobs[32]);
  /* Cancel a middle queue entry; all remaining jobs retain FIFO order. */
  tt_int_op(CANCEL(&jobs[40], 0), OP_EQ, PROTOCOL_BUDGET_OK);
  tt_int_op(CANCEL(&jobs[40], 0), OP_EQ, PROTOCOL_BUDGET_OK);
  for (unsigned i = 1; i <= 32; ++i)
    tt_int_op(COMPLETE(&jobs[i], 0), OP_EQ, PROTOCOL_BUDGET_OK);
  for (unsigned i = 33; i < 160; ++i) {
    if (i == 40)
      continue;
    tt_int_op(protocol_budget_start_next(&owner, 0, &selected), OP_EQ,
              PROTOCOL_BUDGET_OK);
    tt_ptr_op(selected, OP_EQ, &jobs[i]);
    tt_int_op(COMPLETE(selected, 0), OP_EQ, PROTOCOL_BUDGET_OK);
  }
  tt_uint_op(owner.running, OP_EQ, 0);
  tt_uint_op(owner.waiting, OP_EQ, 0);
  tt_uint_op(slot.jobs, OP_EQ, 0);
  tt_uint_op(owner.arena_used, OP_EQ, SLOT_BYTES);
  tt_u64_op(owner.attempts_started, OP_EQ, 159);
 done:
  ;
}

static void
test_protocol_budget_rate_and_no_refund(void *arg)
{
  protocol_budget_t owner;
  protocol_budget_slot_t slot = {0};
  protocol_budget_job_t job = {0}, *selected = NULL;
  uint64_t delay;
  (void)arg;
  tt_int_op(protocol_budget_init(&owner, NULL, 0), OP_EQ, PROTOCOL_BUDGET_OK);
  tt_int_op(SLOT_INIT(&owner, &slot, SLOT_BYTES, 30000, 0), OP_EQ,
            PROTOCOL_BUDGET_OK);
  for (unsigned i = 0; i < 512; ++i) {
    tt_int_op(SUBMIT(&slot, &job, PROTOCOL_BUDGET_HPKE, JOB_BYTES, 0), OP_EQ,
              PROTOCOL_BUDGET_OK);
    tt_int_op(protocol_budget_start_next(&owner, 0, &selected), OP_EQ,
              PROTOCOL_BUDGET_OK);
    /* Completion of failed or successful primitives has the same accounting. */
    tt_int_op(COMPLETE(&job, 0), OP_EQ, PROTOCOL_BUDGET_OK);
  }
  tt_u64_op(owner.attempts_started, OP_EQ, 512);
  tt_u64_op(owner.crypto_credit_milli, OP_EQ, 0);
  tt_int_op(SUBMIT(&slot, &job, PROTOCOL_BUDGET_HPKE, JOB_BYTES, 0), OP_EQ,
            PROTOCOL_BUDGET_OK);
  tt_int_op(protocol_budget_next_wakeup(&owner, 0, &delay), OP_EQ,
            PROTOCOL_BUDGET_OK);
  tt_u64_op(delay, OP_EQ, 4);
  tt_int_op(protocol_budget_next_wakeup(&owner, 3, &delay), OP_EQ,
            PROTOCOL_BUDGET_OK);
  tt_u64_op(delay, OP_EQ, 1);
  tt_int_op(protocol_budget_start_next(&owner, 3, &selected), OP_EQ,
            PROTOCOL_BUDGET_WAIT);
  tt_u64_op(owner.crypto_credit_milli, OP_EQ, 768);
  tt_int_op(protocol_budget_start_next(&owner, 4, &selected), OP_EQ,
            PROTOCOL_BUDGET_OK);
  tt_u64_op(owner.crypto_credit_milli, OP_EQ, 24);
  tt_int_op(COMPLETE(&job, 4), OP_EQ, PROTOCOL_BUDGET_OK);
  tt_int_op(COMPLETE(&job, 4), OP_EQ, PROTOCOL_BUDGET_OK);
  tt_u64_op(owner.crypto_credit_milli, OP_EQ, 24);
  tt_int_op(SUBMIT(&slot, &job, PROTOCOL_BUDGET_SIGNATURE, JOB_BYTES, 1000),
            OP_EQ, PROTOCOL_BUDGET_OK);
  tt_int_op(CANCEL(&job, 1000), OP_EQ, PROTOCOL_BUDGET_OK);
  tt_u64_op(owner.crypto_credit_milli, OP_EQ, 255000);
  tt_u64_op(owner.attempts_started, OP_EQ, 513);
 done:
  ;
}

static void
test_protocol_budget_expiry_and_cost(void *arg)
{
  protocol_budget_t owner;
  protocol_budget_slot_t slot = {0};
  protocol_budget_job_t first = {0}, second = {0}, *selected = NULL;
  uint32_t used;
  (void)arg;
  tt_int_op(protocol_budget_init(&owner, NULL, 0), OP_EQ, PROTOCOL_BUDGET_OK);
  tt_int_op(SLOT_INIT(&owner, &slot, SLOT_BYTES, 1100, 0), OP_EQ,
            PROTOCOL_BUDGET_OK);
  tt_int_op(SUBMIT(&slot, &first, PROTOCOL_BUDGET_HPKE, JOB_BYTES, 0), OP_EQ,
            PROTOCOL_BUDGET_OK);
  tt_int_op(SUBMIT(&slot, &second, PROTOCOL_BUDGET_HPKE, JOB_BYTES, 500), OP_EQ,
            PROTOCOL_BUDGET_OK);
  used = owner.arena_used;
  tt_int_op(protocol_budget_start_next(&owner, 1000, &selected), OP_EQ,
            PROTOCOL_BUDGET_EXPIRED);
  tt_ptr_op(selected, OP_EQ, &first);
  tt_uint_op(owner.arena_used, OP_EQ, used);
  tt_uint_op(owner.waiting, OP_EQ, 2);
  tt_u64_op(owner.attempts_started, OP_EQ, 0);
  tt_int_op(CANCEL(selected, 1000), OP_EQ, PROTOCOL_BUDGET_OK);
  tt_int_op(protocol_budget_start_next(&owner, 1000, &selected), OP_EQ,
            PROTOCOL_BUDGET_OK);
  tt_ptr_op(selected, OP_EQ, &second);
  tt_int_op(FINISH(&slot, sizeof(slot), 1000), OP_EQ,
            PROTOCOL_BUDGET_BAD_STATE);
  /* Expiry cannot free memory still held by an actual primitive. */
  tt_int_op(EXPIRE(&slot, 1100), OP_EQ, PROTOCOL_BUDGET_WAIT);
  tt_uint_op(owner.running, OP_EQ, 1);
  tt_int_op(COMPLETE(&second, 1100), OP_EQ, PROTOCOL_BUDGET_EXPIRED);
  tt_uint_op(owner.arena_used, OP_EQ, SLOT_BYTES);
  tt_int_op(EXPIRE(&slot, 1100), OP_EQ, PROTOCOL_BUDGET_OK);
  tt_uint_op(owner.arena_used, OP_EQ, 0);
  /* Include base+job actual allocations in the 16 KiB per-slot cap. */
  tt_int_op(SLOT_INIT(&owner, &slot, PROTOCOL_BUDGET_SLOT_BYTES - JOB_BYTES,
                     30000, 1100), OP_EQ, PROTOCOL_BUDGET_OK);
  tt_int_op(SUBMIT(&slot, &first, PROTOCOL_BUDGET_SIGNATURE, JOB_BYTES, 1100),
            OP_EQ, PROTOCOL_BUDGET_OK);
  tt_int_op(SUBMIT(&slot, &second, PROTOCOL_BUDGET_SIGNATURE, JOB_BYTES, 1100),
            OP_EQ, PROTOCOL_BUDGET_REFUSE);
  tt_uint_op(owner.arena_used, OP_EQ, PROTOCOL_BUDGET_SLOT_BYTES);
 done:
  ;
}

static void
test_protocol_budget_generation_clock(void *arg)
{
  protocol_budget_t owner, other;
  protocol_budget_slot_t slot = {0};
  protocol_budget_job_t job = {0}, *selected = NULL;
  uint64_t old_slot, old_job, current_job, credit;
  (void)arg;
  tt_int_op(protocol_budget_init(&owner, NULL, 100), OP_EQ,
            PROTOCOL_BUDGET_OK);
  tt_int_op(protocol_budget_init(&other, NULL, 100), OP_EQ,
            PROTOCOL_BUDGET_OK);
  tt_int_op(SLOT_INIT(&owner, &slot, SLOT_BYTES, 200, 100), OP_EQ,
            PROTOCOL_BUDGET_OK);
  old_slot = slot.generation;
  tt_int_op(SUBMIT(&slot, &job, PROTOCOL_BUDGET_SIGNATURE, JOB_BYTES, 100), OP_EQ,
            PROTOCOL_BUDGET_OK);
  old_job = job.generation;
  tt_int_op(protocol_budget_start_next(&owner, 100, &selected), OP_EQ,
            PROTOCOL_BUDGET_OK);
  credit = owner.crypto_credit_milli;
  tt_int_op(COMPLETE(&job, 99), OP_EQ, PROTOCOL_BUDGET_CLOCK_ERROR);
  tt_uint_op(owner.running, OP_EQ, 1);
  tt_u64_op(owner.crypto_credit_milli, OP_EQ, credit);
  tt_int_op(COMPLETE(&job, 100), OP_EQ, PROTOCOL_BUDGET_OK);
  tt_int_op(EXPIRE(&slot, 200), OP_EQ, PROTOCOL_BUDGET_OK);
  tt_int_op(SLOT_INIT(&other, &slot, SLOT_BYTES, 300, 200), OP_EQ,
            PROTOCOL_BUDGET_BAD_STATE);
  tt_int_op(SLOT_INIT(&owner, &slot, SLOT_BYTES, UINT64_MAX, 200), OP_EQ,
            PROTOCOL_BUDGET_OK);
  tt_int_op(protocol_budget_slot_expire(&slot, old_slot, 300), OP_EQ,
            PROTOCOL_BUDGET_BAD_STATE);
  tt_int_op(SUBMIT(&slot, &job, PROTOCOL_BUDGET_NATIVE_SETUP, JOB_BYTES, 200),
            OP_EQ, PROTOCOL_BUDGET_OK);
  current_job = job.generation;
  tt_int_op(protocol_budget_cancel(&job, old_job, 200), OP_EQ,
            PROTOCOL_BUDGET_BAD_STATE);
  tt_int_op(protocol_budget_start_next(&owner, 200, &selected), OP_EQ,
            PROTOCOL_BUDGET_OK);
  tt_int_op(protocol_budget_complete(&job, old_job, 200), OP_EQ,
            PROTOCOL_BUDGET_BAD_STATE);
  tt_uint_op(owner.running, OP_EQ, 1);
  tt_int_op(protocol_budget_complete(&job, current_job, UINT64_MAX), OP_EQ,
            PROTOCOL_BUDGET_EXPIRED);
  tt_u64_op(owner.crypto_credit_milli, OP_EQ, 512000);
  tt_int_op(EXPIRE(&slot, UINT64_MAX), OP_EQ, PROTOCOL_BUDGET_OK);
  tt_int_op(SLOT_INIT(&owner, &slot, SLOT_BYTES, UINT64_MAX, 0), OP_EQ,
            PROTOCOL_BUDGET_CLOCK_ERROR);
  /* Generation exhaustion fails before wrap or new allocations. */
  tt_int_op(protocol_budget_init(&owner, NULL, 0), OP_EQ, PROTOCOL_BUDGET_OK);
  owner.last_generation = UINT64_MAX;
  tt_int_op(SLOT_INIT(&owner, &slot, SLOT_BYTES, 30000, 0), OP_EQ,
            PROTOCOL_BUDGET_REFUSE);
  tt_uint_op(owner.slots, OP_EQ, 0);
 done:
  ;
}

static void
test_protocol_budget_lower_ceilings(void *arg)
{
  protocol_budget_t owner;
  protocol_budget_limits_t limits;
  protocol_budget_slot_t slot = {0};
  protocol_budget_job_t jobs[3] = {{0}}, *selected = NULL;
  (void)arg;
  protocol_budget_default_limits(&limits);
  limits.max_slots = 2;
  limits.arena_bytes = 4096;
  limits.max_slot_bytes = 1024;
  limits.crypto_rate = 1;
  limits.crypto_burst = 1;
  limits.max_running = 1;
  limits.max_waiting = 2;
  limits.max_wait_ms = 100;
  tt_int_op(protocol_budget_init(&owner, &limits, 0), OP_EQ,
            PROTOCOL_BUDGET_OK);
  tt_int_op(SLOT_INIT(&owner, &slot, SLOT_BYTES, 30000, 0), OP_EQ,
            PROTOCOL_BUDGET_OK);
  for (unsigned i = 0; i < 2; ++i)
    tt_int_op(SUBMIT(&slot, &jobs[i], PROTOCOL_BUDGET_SIGNATURE,
                     JOB_BYTES, 0), OP_EQ, PROTOCOL_BUDGET_OK);
  tt_int_op(SUBMIT(&slot, &jobs[2], PROTOCOL_BUDGET_HPKE, JOB_BYTES, 0), OP_EQ,
            PROTOCOL_BUDGET_REFUSE);
  tt_int_op(protocol_budget_start_next(&owner, 0, &selected), OP_EQ,
            PROTOCOL_BUDGET_OK);
  tt_ptr_op(selected, OP_EQ, &jobs[0]);
  tt_int_op(protocol_budget_start_next(&owner, 0, &selected), OP_EQ,
            PROTOCOL_BUDGET_WAIT);
  tt_int_op(COMPLETE(&jobs[0], 0), OP_EQ, PROTOCOL_BUDGET_OK);
  tt_int_op(protocol_budget_start_next(&owner, 99, &selected), OP_EQ,
            PROTOCOL_BUDGET_WAIT);
  tt_u64_op(owner.crypto_credit_milli, OP_EQ, 99);
  tt_int_op(protocol_budget_start_next(&owner, 100, &selected), OP_EQ,
            PROTOCOL_BUDGET_EXPIRED);
  tt_ptr_op(selected, OP_EQ, &jobs[1]);
  tt_int_op(CANCEL(selected, 100), OP_EQ, PROTOCOL_BUDGET_OK);
  tt_u64_op(owner.attempts_started, OP_EQ, 1);
  tt_u64_op(slot.expires_ms, OP_EQ, 30000);
  tt_int_op(EXPIRE(&slot, 30000), OP_EQ, PROTOCOL_BUDGET_OK);
  /* Same profile, smaller local arena: actual per-job overhead blocks a job
   * even though its slot and all job-count ceilings still have room. */
  limits.arena_bytes = SLOT_BYTES + JOB_BYTES - 1;
  tt_int_op(protocol_budget_init(&owner, &limits, 30000), OP_EQ,
            PROTOCOL_BUDGET_OK);
  tt_int_op(SLOT_INIT(&owner, &slot, SLOT_BYTES, 60000, 30000), OP_EQ,
            PROTOCOL_BUDGET_OK);
  tt_int_op(SUBMIT(&slot, &jobs[0], PROTOCOL_BUDGET_HPKE, JOB_BYTES, 30000),
            OP_EQ, PROTOCOL_BUDGET_REFUSE);
  tt_uint_op(owner.arena_used, OP_EQ, SLOT_BYTES);
 done:
  ;
}

static void
test_protocol_budget_shared_backing(void *arg)
{
  protocol_budget_t owner;
  protocol_budget_limits_t limits;
  protocol_budget_memory_t memory = {0};
  protocol_budget_slot_t slot = {0};
  uint64_t generation;
  (void)arg;
  protocol_budget_default_limits(&limits);
  limits.arena_bytes = 65536 + SLOT_BYTES;
  tt_int_op(protocol_budget_init(&owner, &limits, 0), OP_EQ,
            PROTOCOL_BUDGET_OK);
  tt_int_op(protocol_budget_memory_reserve(&owner, &memory, 65536, 0), OP_EQ,
            PROTOCOL_BUDGET_OK);
  generation = memory.generation;
  tt_int_op(SLOT_INIT(&owner, &slot, SLOT_BYTES, 30000, 0), OP_EQ,
            PROTOCOL_BUDGET_OK);
  tt_uint_op(owner.arena_used, OP_EQ, 65536 + SLOT_BYTES);
  tt_uint_op(owner.memory_reservations, OP_EQ, 1);
  tt_int_op(protocol_budget_memory_release(&memory, generation, 0), OP_EQ,
            PROTOCOL_BUDGET_OK);
  tt_int_op(protocol_budget_memory_release(&memory, generation, 0), OP_EQ,
            PROTOCOL_BUDGET_OK);
  tt_uint_op(owner.memory_reservations, OP_EQ, 0);
  tt_uint_op(owner.arena_used, OP_EQ, SLOT_BYTES);
  tt_int_op(protocol_budget_memory_reserve(&owner, &memory, UINT32_MAX, 0),
            OP_EQ, PROTOCOL_BUDGET_REFUSE);
  tt_int_op(protocol_budget_memory_reserve(&owner, &memory, 65536, 0), OP_EQ,
            PROTOCOL_BUDGET_OK);
  tt_int_op(protocol_budget_memory_release(&memory, generation, 0), OP_EQ,
            PROTOCOL_BUDGET_BAD_STATE);
  tt_uint_op(owner.arena_used, OP_EQ, 65536 + SLOT_BYTES);
  tt_u64_op(owner.crypto_credit_milli, OP_EQ, 512000);
 done:
  ;
}

#define BUDGET_TEST(name) { #name, test_protocol_budget_##name, 0, NULL, NULL }
struct testcase_t protocol_budget_tests[] = {
  BUDGET_TEST(config),
  BUDGET_TEST(slots),
  BUDGET_TEST(full_arena),
  BUDGET_TEST(fifo_and_concurrency),
  BUDGET_TEST(rate_and_no_refund),
  BUDGET_TEST(expiry_and_cost),
  BUDGET_TEST(generation_clock),
  BUDGET_TEST(lower_ceilings),
  BUDGET_TEST(shared_backing),
  END_OF_TESTCASES
};
