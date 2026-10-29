/* Copyright (c) 2026, The El Tor Project. */
/* See LICENSE for licensing information. */
#include "orconfig.h"
#include "feature/payment/payment_workqueue.h"
#include "feature/payment/payment_resources.h"
#include "lib/malloc/malloc.h"
#include "lib/crypt_ops/crypto_util.h"
#include "lib/evloop/timers.h"
#include "lib/time/compat_time.h"
#include <string.h>

struct payment_work_t {
  protocol_budget_job_t job;
  protocol_budget_slot_t native_slot;
  protocol_budget_slot_t *slot;
  protocol_budget_memory_t memory;
  struct payment_work_t *next;
  payment_work_start_fn start;
  payment_work_drop_fn drop;
  void *arg;
  uint32_t retained_bytes;
  protocol_budget_work_t kind;
  bool native;
};
static payment_work_t *works;
static tor_timer_t *work_timer;
static protocol_budget_memory_t work_timer_memory;
static bool dispatching;
static void schedule_work(void);

static uint64_t
cleanup_now(protocol_budget_t *owner)
{
  uint64_t now=monotime_absolute_msec();
  return now<owner->last_ms?owner->last_ms:now;
}

static payment_work_t *
find_work(protocol_budget_job_t *job)
{
  for (payment_work_t *work=works;work;work=work->next)
    if (&work->job==job) return work;
  return NULL;
}

static void
free_work(payment_work_t *work)
{
  payment_work_t **link=&works;
  while (*link && *link!=work) link=&(*link)->next;
  if (*link) *link=work->next;
  if (work->native)
    (void)protocol_budget_native_slot_retire(&work->native_slot,
        work->native_slot.generation,cleanup_now(work->slot->owner));
  protocol_budget_memory_t memory=work->memory;
  memwipe(work,0,sizeof(*work)); tor_free(work);
  (void)payment_resources_release(&memory);
  schedule_work();
}

payment_work_t *
payment_work_reserve(protocol_budget_slot_t *slot, protocol_budget_work_t kind,
                       size_t retained_bytes, uint64_t deadline_ms)
{
  protocol_budget_t *owner=payment_resources_protocol();
  uint64_t now=monotime_absolute_msec();
  size_t overhead=sizeof(payment_work_t)+sizeof(protocol_budget_job_t)+
                  sizeof(protocol_budget_slot_t);
  if ((kind!=PROTOCOL_BUDGET_NATIVE_SETUP && !slot) ||
      retained_bytes>owner->limits.max_slot_bytes ||
      overhead>owner->limits.max_slot_bytes-retained_bytes ||
      now>=deadline_ms ||
      (slot && (slot->owner!=owner || slot->state!=PROTOCOL_BUDGET_SLOT_LIVE)))
    return NULL;
  protocol_budget_memory_t memory={0};
  if (payment_resources_reserve(&memory,sizeof(payment_work_t)+retained_bytes)!=
      PROTOCOL_BUDGET_OK) return NULL;
  if (!work_timer_memory.active &&
      payment_resources_reserve(&work_timer_memory,
          timer_memory_cost()+sizeof(work_timer_memory))!=PROTOCOL_BUDGET_OK) {
    payment_resources_release(&memory); return NULL;
  }
  payment_work_t *work=tor_malloc_zero(sizeof(*work));
  work->memory=memory; work->kind=kind;
  work->retained_bytes=(uint32_t)retained_bytes;
  if (slot) work->slot=slot;
  else {
    if (protocol_budget_native_slot_reserve(owner,&work->native_slot,
          sizeof(work->native_slot),deadline_ms,now)!=PROTOCOL_BUDGET_OK) {
      memwipe(work,0,sizeof(*work)); tor_free(work);
      payment_resources_release(&memory);
      if (!works) payment_resources_release(&work_timer_memory);
      return NULL;
    }
    work->native=true; work->slot=&work->native_slot;
  }
  work->next=works; works=work;
  return work;
}

static void
work_timer_callback(tor_timer_t *timer, void *arg, const monotime_t *now)
{
  (void)timer; (void)arg; (void)now;
  payment_work_dispatch();
}

static void
schedule_work(void)
{
  if (dispatching) return;
  protocol_budget_t *owner=payment_resources_protocol();
  uint64_t delay;
  if (protocol_budget_next_wakeup(owner,monotime_absolute_msec(),&delay)!=
      PROTOCOL_BUDGET_OK) {
    if (work_timer) timer_disable(work_timer);
    return;
  }
  if (!work_timer) work_timer=timer_new(work_timer_callback,NULL);
  if (!delay) delay=1;
  if (delay>1000) delay=1000;
  struct timeval tv={(time_t)(delay/1000),(suseconds_t)(delay%1000)*1000};
  timer_schedule(work_timer,&tv);
}

int
payment_work_queue(payment_work_t *work, payment_work_start_fn start,
                     payment_work_drop_fn drop, void *arg)
{
  if (!work || !start || !drop || work->start ||
      work->job.state!=PROTOCOL_BUDGET_JOB_UNUSED) return -1;
  protocol_budget_result_t result=protocol_budget_submit(work->slot,
      work->slot->generation,&work->job,work->kind,
      work->retained_bytes+sizeof(work->job),monotime_absolute_msec());
  if (result!=PROTOCOL_BUDGET_OK) return -1;
  work->start=start; work->drop=drop; work->arg=arg;
  payment_work_dispatch();
  return 0;
}

void
payment_work_dispatch(void)
{
  if (dispatching) return;
  dispatching=true;
  protocol_budget_t *owner=payment_resources_protocol();
  /* At most the fixed waiting ceiling is handled per event-loop callback. */
  for (uint32_t i=0;i<PROTOCOL_BUDGET_WAITING;++i) {
    payment_work_t *work=find_work(owner->head);
    if (!work) break;
    protocol_budget_job_t *job=NULL;
    protocol_budget_result_t result=protocol_budget_start_next(owner,
        monotime_absolute_msec(),&job);
    if (result==PROTOCOL_BUDGET_EXPIRED) {
      (void)protocol_budget_cancel(job,job->generation,cleanup_now(owner));
      work->drop(work->arg);
      free_work(work);
    } else if (result==PROTOCOL_BUDGET_OK) {
      if (work->start(work,work->arg)<0) {
        work->drop(work->arg);
        (void)protocol_budget_complete(job,job->generation,cleanup_now(owner));
        free_work(work);
      }
    } else break;
  }
  dispatching=false;
  schedule_work();
}

bool
payment_work_cancel(payment_work_t *work)
{
  if (!work || work->job.state!=PROTOCOL_BUDGET_JOB_WAITING) return false;
  if (protocol_budget_cancel(&work->job,work->job.generation,
                              cleanup_now(work->slot->owner))!=PROTOCOL_BUDGET_OK)
    return false;
  work->drop(work->arg);
  free_work(work);
  payment_work_dispatch();
  return true;
}

bool
payment_work_result_timely(const payment_work_t *work)
{
  if (!work || work->job.state!=PROTOCOL_BUDGET_JOB_RUNNING) return false;
  uint64_t now=monotime_absolute_msec();
  return now>=work->slot->owner->last_ms && now<work->slot->expires_ms;
}

bool
payment_work_complete(payment_work_t *work)
{
  if (!work || work->job.state!=PROTOCOL_BUDGET_JOB_RUNNING) return false;
  bool timely=payment_work_result_timely(work);
  protocol_budget_result_t result=protocol_budget_complete(&work->job,
      work->job.generation,cleanup_now(work->slot->owner));
  free_work(work);
  payment_work_dispatch();
  return timely && result==PROTOCOL_BUDGET_OK;
}

void
payment_work_release(payment_work_t *work)
{
  if (work && !work->start && work->job.state==PROTOCOL_BUDGET_JOB_UNUSED)
    free_work(work);
}

int
payment_workqueue_free_all(void)
{
  if (works) return -1;
  timer_free(work_timer);
  payment_resources_release(&work_timer_memory);
  return 0;
}
