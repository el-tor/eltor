/* Copyright (c) 2026, The El Tor Project. */
/* See LICENSE for licensing information. */
#define TOR_TIMERS_PRIVATE
#include "orconfig.h"
#include "core/or/or.h"
#include "feature/payment/payment_workqueue.h"
#include "feature/payment/payment_resources.h"
#include "lib/evloop/timers.h"
#include "lib/time/compat_time.h"
#include "lib/malloc/malloc.h"
#include "test/test.h"

typedef struct native_test_job_t {
  payment_work_t *work;
  char *buffer;
  unsigned id, starts, drops;
  bool fail_start;
} native_test_job_t;
static unsigned order[200], n_order;

static int
native_start(payment_work_t *work, void *arg)
{
  native_test_job_t *job=arg;
  job->work=work;
  ++job->starts; order[n_order++]=job->id;
  return job->fail_start?-1:0;
}
static void
native_drop(void *arg)
{
  native_test_job_t *job=arg;
  ++job->drops; tor_free(job->buffer); job->work=NULL;
}
static int
native_prepare(native_test_job_t *job, unsigned id, uint64_t deadline)
{
  job->id=id;
  job->work=payment_work_reserve(NULL,PROTOCOL_BUDGET_NATIVE_SETUP,256,deadline);
  if (!job->work) return -1;
  job->buffer=tor_malloc_zero(256);
  if (payment_work_queue(job->work,native_start,native_drop,job)<0) {
    tor_free(job->buffer); payment_work_release(job->work); job->work=NULL;
    return -1;
  }
  return 0;
}
static bool
native_complete(native_test_job_t *job)
{
  payment_work_t *work=job->work;
  tor_free(job->buffer); job->work=NULL;
  return payment_work_complete(work);
}
static void
native_init(void)
{
  n_order=0; timers_initialize(); monotime_enable_test_mocking();
  monotime_set_mock_time_nsec(INT64_C(1000000000));
  monotime_coarse_set_mock_time_nsec(INT64_C(1000000000));
}
static void
native_cleanup(native_test_job_t *jobs, size_t n)
{
  for (size_t i=0;i<n;++i) {
    if (!jobs[i].work) continue;
    if (!payment_work_cancel(jobs[i].work)) (void)native_complete(&jobs[i]);
  }
  (void)payment_workqueue_free_all(); (void)payment_resources_free_all();
  timers_shutdown(); monotime_disable_test_mocking();
}

static void
test_native_fifo(void *arg)
{
  (void)arg;
  native_test_job_t jobs[161]={0};
  native_init();
  for (unsigned i=0;i<160;++i) tt_int_op(native_prepare(&jobs[i],i,30000),OP_EQ,0);
  protocol_budget_t *owner=payment_resources_protocol();
  tt_u64_op(owner->running,OP_EQ,32); tt_u64_op(owner->waiting,OP_EQ,128);
  tt_uint_op(n_order,OP_EQ,32);
  tt_int_op(native_prepare(&jobs[160],160,30000),OP_EQ,-1);
  tt_assert(!payment_work_cancel(jobs[0].work)); /* actual running owns memory */
  tt_assert(native_complete(&jobs[0]));
  tt_uint_op(n_order,OP_EQ,33); tt_uint_op(order[32],OP_EQ,32);
  tt_u64_op(owner->running,OP_EQ,32); tt_u64_op(owner->waiting,OP_EQ,127);
 done:
  native_cleanup(jobs,ARRAY_LENGTH(jobs));
}

static void
test_native_credit_and_expiry(void *arg)
{
  (void)arg;
  native_test_job_t jobs[3]={0};
  protocol_budget_limits_t limits;
  native_init(); protocol_budget_default_limits(&limits);
  limits.crypto_burst=1; limits.max_running=1;
  tt_int_op(payment_resources_configure(&limits),OP_EQ,0);
  tt_int_op(native_prepare(&jobs[0],0,30000),OP_EQ,0);
  tt_assert(native_complete(&jobs[0]));
  tt_int_op(native_prepare(&jobs[1],1,30000),OP_EQ,0);
  tt_uint_op(jobs[1].starts,OP_EQ,0);
  monotime_set_mock_time_nsec(INT64_C(1003000000)); payment_work_dispatch();
  tt_uint_op(jobs[1].starts,OP_EQ,0);
  monotime_set_mock_time_nsec(INT64_C(1004000000)); payment_work_dispatch();
  tt_uint_op(jobs[1].starts,OP_EQ,1);
  tt_u64_op(payment_resources_protocol()->attempts_started,OP_EQ,2);
  tt_int_op(native_prepare(&jobs[2],2,30000),OP_EQ,0);
  monotime_set_mock_time_nsec(INT64_C(2004000000)); payment_work_dispatch();
  tt_uint_op(jobs[2].drops,OP_EQ,1); tt_uint_op(jobs[2].starts,OP_EQ,0);
  tt_assert(native_complete(&jobs[1]));
  tt_u64_op(payment_resources_protocol()->attempts_started,OP_EQ,2);
 done:
  native_cleanup(jobs,ARRAY_LENGTH(jobs));
}

static void
test_native_failure_and_deadline(void *arg)
{
  (void)arg;
  native_test_job_t jobs[2]={0};
  native_init(); jobs[0].fail_start=true;
  tt_int_op(native_prepare(&jobs[0],0,5000),OP_EQ,0);
  tt_uint_op(jobs[0].drops,OP_EQ,1); tt_ptr_op(jobs[0].work,OP_EQ,NULL);
  tt_u64_op(payment_resources_protocol()->running,OP_EQ,0);
  tt_u64_op(payment_resources_protocol()->slots,OP_EQ,0);
  tt_int_op(native_prepare(&jobs[1],1,5000),OP_EQ,0);
  monotime_set_mock_time_nsec(INT64_C(5000000000));
  tt_assert(!native_complete(&jobs[1])); /* late result is never installed */
  tt_u64_op(payment_resources_protocol()->running,OP_EQ,0);
  tt_u64_op(payment_resources_protocol()->slots,OP_EQ,0);
  tt_ptr_op(payment_work_reserve(NULL,PROTOCOL_BUDGET_NATIVE_SETUP,16384,6000),OP_EQ,NULL);
 done:
  native_cleanup(jobs,ARRAY_LENGTH(jobs));
}

typedef struct tiny_fixture_t {
  payment_work_t *work;
  char *buffer;
  unsigned starts, drops;
  bool fail;
} tiny_fixture_t;
static int tiny_start(payment_work_t *work, void *arg) {
  tiny_fixture_t *f=arg; (void)work; ++f->starts; return f->fail?-1:0;
}
static void tiny_drop(void *arg) {
  tiny_fixture_t *f=arg; ++f->drops; tor_free(f->buffer); f->work=NULL;
}
static bool tiny_queue(tiny_fixture_t *f, protocol_budget_slot_t *slot,
                        uint64_t deadline) {
  f->work=payment_work_reserve(slot,slot?PROTOCOL_BUDGET_SIGNATURE:
                               PROTOCOL_BUDGET_NATIVE_SETUP,64,deadline);
  if (!f->work) return false;
  f->buffer=tor_malloc_zero(64);
  if (payment_work_queue(f->work,tiny_start,tiny_drop,f)<0) {
    tor_free(f->buffer); payment_work_release(f->work); f->work=NULL;
    return false;
  }
  return true;
}
static void tiny_cleanup(tiny_fixture_t *f) {
  if (!f->work || payment_work_cancel(f->work)) return;
  tor_free(f->buffer); payment_work_t *w=f->work; f->work=NULL;
  (void)payment_work_complete(w);
}
static void tiny_time(uint64_t ms) {
  monotime_set_mock_time_nsec((int64_t)ms*1000000);
  monotime_coarse_set_mock_time_nsec((int64_t)ms*1000000);
}
static int tiny_limits(void) {
  protocol_budget_limits_t l; protocol_budget_default_limits(&l);
  l.max_slots=4; l.max_slot_bytes=1024; l.arena_bytes=65536;
  l.crypto_rate=l.crypto_burst=1; l.max_running=1; l.max_waiting=2;
  l.max_wait_ms=10; return payment_resources_configure(&l);
}
static void test_tiny_overload_and_cancel(void *arg) {
  tiny_fixture_t a={0},b={0},c={0},refused={0};
  protocol_budget_t *o; uint32_t retained,baseline; (void)arg;
  monotime_enable_test_mocking(); tiny_time(1000); timers_initialize();
  tt_int_op(tiny_limits(),OP_EQ,0); o=payment_resources_protocol();
  baseline=o->arena_used;
  tt_assert(tiny_queue(&a,NULL,2000)); tt_assert(tiny_queue(&b,NULL,2000));
  tt_assert(tiny_queue(&c,NULL,2000));
  tt_uint_op(o->running,OP_EQ,1); tt_uint_op(o->waiting,OP_EQ,2);
  tt_uint_op(o->slots,OP_EQ,3);
  tt_assert(!tiny_queue(&refused,NULL,2000));
  tt_ptr_op(refused.buffer,OP_EQ,NULL); tt_uint_op(o->slots,OP_EQ,3);
  tt_assert(payment_work_cancel(b.work)); tt_uint_op(b.drops,OP_EQ,1);
  tt_ptr_op(b.buffer,OP_EQ,NULL); tt_uint_op(o->waiting,OP_EQ,1);
  tt_uint_op(o->slots,OP_EQ,2); retained=o->arena_used;
  tt_assert(!payment_work_cancel(a.work));
  tt_uint_op(o->running,OP_EQ,1); tt_uint_op(o->arena_used,OP_EQ,retained);
  tiny_time(1011); timers_run_pending();
  tt_uint_op(c.drops,OP_EQ,1); tt_uint_op(c.starts,OP_EQ,0);
  tt_ptr_op(c.buffer,OP_EQ,NULL); tt_uint_op(o->waiting,OP_EQ,0);
  tt_uint_op(o->slots,OP_EQ,1);
  tiny_time(2001); timers_run_pending();
  tt_uint_op(o->running,OP_EQ,1); tt_uint_op(o->slots,OP_EQ,1);
  tt_uint_op(o->arena_used,OP_GT,baseline); tt_ptr_op(a.buffer,OP_NE,NULL);
  tor_free(a.buffer); payment_work_t *work=a.work; a.work=NULL;
  tt_assert(!payment_work_complete(work));
  tt_uint_op(o->running,OP_EQ,0); tt_uint_op(o->slots,OP_EQ,0);
  tt_u64_op(o->attempts_started,OP_EQ,1);
  tt_int_op(payment_workqueue_free_all(),OP_EQ,0);
  tt_uint_op(o->arena_used,OP_EQ,baseline);
 done:
  tiny_cleanup(&a); tiny_cleanup(&b); tiny_cleanup(&c); tiny_cleanup(&refused);
  (void)payment_workqueue_free_all(); (void)payment_resources_free_all();
  timers_shutdown(); monotime_disable_test_mocking();
}
static void test_tiny_financial_retention(void *arg) {
  tiny_fixture_t f={0}; protocol_budget_slot_t s={0};
  protocol_budget_t *o; (void)arg;
  monotime_enable_test_mocking(); tiny_time(1000); timers_initialize();
  tt_int_op(tiny_limits(),OP_EQ,0); o=payment_resources_protocol();
  tt_int_op(protocol_budget_slot_reserve(o,&s,128,2000,1000),OP_EQ,
            PROTOCOL_BUDGET_OK);
  tt_assert(tiny_queue(&f,&s,2000));
  tor_free(f.buffer); payment_work_t *work=f.work; f.work=NULL;
  tt_assert(payment_work_complete(work));
  tt_uint_op(o->running,OP_EQ,0); tt_uint_op(o->slots,OP_EQ,1);
  tt_uint_op(s.state,OP_EQ,PROTOCOL_BUDGET_SLOT_LIVE);
  tt_int_op(protocol_budget_native_slot_retire(&s,s.generation,1000),OP_EQ,
            PROTOCOL_BUDGET_BAD_STATE);
  tt_int_op(protocol_budget_slot_finish(&s,s.generation,sizeof(s),1000),OP_EQ,
            PROTOCOL_BUDGET_OK); tt_uint_op(o->slots,OP_EQ,1);
  tt_int_op(protocol_budget_slot_expire(&s,s.generation,1999),OP_EQ,
            PROTOCOL_BUDGET_WAIT);
  tiny_time(2000);
  tt_int_op(protocol_budget_slot_expire(&s,s.generation,2000),OP_EQ,
            PROTOCOL_BUDGET_OK);
 done:
  tiny_cleanup(&f);
  if (s.state!=PROTOCOL_BUDGET_SLOT_UNUSED) {
    tiny_time(2000); (void)protocol_budget_slot_expire(&s,s.generation,2000);
  }
  (void)payment_workqueue_free_all(); (void)payment_resources_free_all();
  timers_shutdown(); monotime_disable_test_mocking();
}
static void test_tiny_allocation_and_start_failure(void *arg) {
  tiny_fixture_t f={.fail=true}; protocol_budget_memory_t blocker={0};
  protocol_budget_t *o; uint32_t baseline; (void)arg;
  monotime_enable_test_mocking(); tiny_time(1000); timers_initialize();
  tt_int_op(tiny_limits(),OP_EQ,0); o=payment_resources_protocol();
  baseline=o->arena_used;
  tt_int_op(payment_resources_reserve(&blocker,o->limits.arena_bytes-baseline-1),
            OP_EQ,PROTOCOL_BUDGET_OK);
  tt_assert(!tiny_queue(&f,NULL,2000)); tt_uint_op(o->slots,OP_EQ,0);
  tt_uint_op(o->arena_used,OP_EQ,o->limits.arena_bytes-1);
  tt_int_op(payment_resources_release(&blocker),OP_EQ,PROTOCOL_BUDGET_OK);
  tt_assert(tiny_queue(&f,NULL,2000));
  tt_uint_op(f.starts,OP_EQ,1); tt_uint_op(f.drops,OP_EQ,1);
  tt_ptr_op(f.work,OP_EQ,NULL); tt_ptr_op(f.buffer,OP_EQ,NULL);
  tt_uint_op(o->slots,OP_EQ,0); tt_uint_op(o->running,OP_EQ,0);
  tt_u64_op(o->attempts_started,OP_EQ,1);
 done:
  (void)payment_resources_release(&blocker); tiny_cleanup(&f);
  (void)payment_workqueue_free_all(); (void)payment_resources_free_all();
  timers_shutdown(); monotime_disable_test_mocking();
}

typedef struct sync_probe_t {
  unsigned calls;
  int result;
  bool expire;
} sync_probe_t;

static int
sync_probe(void *arg)
{
  sync_probe_t *probe = arg;
  ++probe->calls;
  if (probe->expire) tiny_time(5000);
  return probe->result;
}

static void
test_native_synchronous_admission(void *arg)
{
  (void)arg;
  native_test_job_t older = {0};
  sync_probe_t probe = {0};
  int result = 123;
  native_init();
  protocol_budget_limits_t limits;
  protocol_budget_default_limits(&limits);
  limits.crypto_rate = limits.crypto_burst = 1;
  limits.max_running = 1;
  tt_int_op(payment_resources_configure(&limits), OP_EQ, 0);
  protocol_budget_t *owner = payment_resources_protocol();
  probe.result = -1; /* Primitive failure consumes the same shared attempt. */
  tt_assert(payment_work_run_sync(64, 5000, sync_probe, &probe, &result));
  tt_int_op(result, OP_EQ, -1); tt_uint_op(probe.calls, OP_EQ, 1);
  tt_u64_op(owner->attempts_started, OP_EQ, 1);
  tt_assert(!payment_work_run_sync(64, 5000, sync_probe, &probe, &result));
  tt_uint_op(probe.calls, OP_EQ, 1);
  tt_uint_op(owner->running, OP_EQ, 0); tt_uint_op(owner->waiting, OP_EQ, 0);
  tt_uint_op(owner->slots, OP_EQ, 0); /* No callback/stack argument retained. */
  tiny_time(1100);
  tt_int_op(native_prepare(&older, 0, 5000), OP_EQ, 0); /* older FIFO waiter */
  tiny_time(2000);
  tt_assert(!payment_work_run_sync(64, 5000, sync_probe, &probe, &result));
  tt_uint_op(older.starts, OP_EQ, 1); tt_uint_op(probe.calls, OP_EQ, 1);
  tt_uint_op(owner->running, OP_EQ, 1); tt_uint_op(owner->waiting, OP_EQ, 0);
  tt_assert(native_complete(&older));
  tiny_time(3000); probe.result = 77;
  tt_assert(payment_work_run_sync(64, 5000, sync_probe, &probe, &result));
  tt_int_op(result, OP_EQ, 77); tt_uint_op(probe.calls, OP_EQ, 2);
  tiny_time(4000); probe.expire = true;
  tt_assert(!payment_work_run_sync(64, 4001, sync_probe, &probe, &result));
  tt_int_op(result, OP_EQ, 77); /* Late primitive output is not published. */
  tt_uint_op(probe.calls, OP_EQ, 3);
  tt_uint_op(owner->running, OP_EQ, 0); tt_uint_op(owner->waiting, OP_EQ, 0);
  tt_uint_op(owner->slots, OP_EQ, 0);
  tt_u64_op(owner->attempts_started, OP_EQ, 4);
 done:
  native_cleanup(&older, 1);
}

struct testcase_t payment_workqueue_tests[]={
  {"fifo",test_native_fifo,TT_FORK,NULL,NULL},
  {"synchronous_admission",test_native_synchronous_admission,TT_FORK,NULL,NULL},
  {"credit_and_expiry",test_native_credit_and_expiry,TT_FORK,NULL,NULL},
  {"failure_and_deadline",test_native_failure_and_deadline,TT_FORK,NULL,NULL},
  {"tiny_overload_and_cancel",test_tiny_overload_and_cancel,TT_FORK,NULL,NULL},
  {"tiny_financial_retention",test_tiny_financial_retention,TT_FORK,NULL,NULL},
  {"tiny_allocation_and_start_failure",test_tiny_allocation_and_start_failure,TT_FORK,NULL,NULL},
  END_OF_TESTCASES
};
