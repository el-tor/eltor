/* Copyright (c) 2003-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2024, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file cpuworker.c
 * \brief Uses the workqueue/threadpool code to farm CPU-intensive activities
 * out to subprocesses.
 *
 * The multithreading backend for this module is in workqueue.c; this module
 * specializes workqueue.c.
 *
 * Right now, we use this infrastructure
 *  <ul><li>for processing onionskins in onion.c
 *      <li>for compressing consensuses in consdiffmgr.c,
 *      <li>for calculating diffs and compressing them in consdiffmgr.c.
 *      <li>and for solving onion service PoW challenges in pow.c.
 *  </ul>
 **/
#define CPUWORKER_PRIVATE
#include "core/or/or.h"
#include "feature/payment/payment_initial.h"
#include "feature/payment/payment_circuit.h"
#include "feature/payment/free_capacity_hooks.h"
#include "feature/payment/payment_workqueue.h"
#include "feature/payment/payment_resources.h"
#include "lib/time/compat_time.h"
#include "core/or/channel.h"
#include "core/or/circuitlist.h"
#include "core/or/connection_or.h"
#include "core/or/congestion_control_common.h"
#include "core/or/congestion_control_flow.h"
#include "app/config/config.h"
#include "lib/crypt_ops/crypto_rand.h"
#include "lib/crypt_ops/crypto_util.h"
#include "core/or/onion.h"
#include "feature/relay/circuitbuild_relay.h"
#include "feature/relay/onion_queue.h"
#include "feature/stats/rephist.h"
#include "feature/relay/router.h"
#include "feature/nodelist/networkstatus.h"
#include "lib/evloop/workqueue.h"
#include "core/crypto/onion_crypto.h"
#include "core/mainloop/cpuworker.h"

#include "core/or/or_circuit_st.h"

static void queue_pending_tasks(void);


static void *
worker_state_new(void *arg)
{
  worker_state_t *ws;
  (void)arg;
  ws = tor_malloc_zero(sizeof(worker_state_t));
  ws->onion_keys = server_onion_keys_new();
  return ws;
}

#define worker_state_free(ws) \
  FREE_AND_NULL(worker_state_t, worker_state_free_, (ws))

static void
worker_state_free_(worker_state_t *ws)
{
  if (!ws)
    return;
  server_onion_keys_free(ws->onion_keys);
  tor_free(ws);
}

static void
worker_state_free_void(void *arg)
{
  worker_state_free_(arg);
}

STATIC threadpool_t *threadpool = NULL;

STATIC uint32_t total_pending_tasks = 0;
static uint32_t max_pending_tasks = 128;

/** Return the consensus parameter max pending tasks per CPU. */
static uint32_t
get_max_pending_tasks_per_cpu(const networkstatus_t *ns)
{
/* Total voodoo. Can we make this more sensible? Maybe, that is why we made it
 * a consensus parameter so our future self can figure out this magic. */
#define MAX_PENDING_TASKS_PER_CPU_DEFAULT 64
#define MAX_PENDING_TASKS_PER_CPU_MIN 1
#define MAX_PENDING_TASKS_PER_CPU_MAX INT32_MAX

  return networkstatus_get_param(ns, "max_pending_tasks_per_cpu",
                                 MAX_PENDING_TASKS_PER_CPU_DEFAULT,
                                 MAX_PENDING_TASKS_PER_CPU_MIN,
                                 MAX_PENDING_TASKS_PER_CPU_MAX);
}

/** Set the max pending tasks per CPU worker. This uses the consensus to check
 * for the allowed number per CPU. The ns parameter can be NULL as in that no
 * consensus is available at the time of setting this value. */
static void
set_max_pending_tasks(const networkstatus_t *ns)
{
  max_pending_tasks =
    get_num_cpus(get_options()) * get_max_pending_tasks_per_cpu(ns);
}

/** Called when the consensus has changed. */
void
cpuworker_consensus_has_changed(const networkstatus_t *ns)
{
  tor_assert(ns);
  set_max_pending_tasks(ns);
}

/** Initialize the cpuworker subsystem. */
int
cpuworker_init(void)
{
  /*
    In our threadpool implementation, half the threads are permissive and
    half are strict (when it comes to running lower-priority tasks). So we
    always make sure we have at least two threads, so that there will be at
    least one thread of each kind.
  */
  const int n_threads = MAX(get_num_cpus(get_options()), 2);
  threadpool = threadpool_new(n_threads,
                              replyqueue_new(0),
                              worker_state_new,
                              worker_state_free_void,
                              NULL);

  if (!threadpool) {
    log_err(LD_GENERAL, "Can't create worker thread pool");
    return -1;
  }

  int r = threadpool_register_reply_event(threadpool, NULL);

  tor_assert(r == 0);

  set_max_pending_tasks(NULL);

  return 0;
}

/** Free all resources allocated by cpuworker. */
void
cpuworker_free_all(void)
{
  threadpool_free(threadpool);
}

/** Return the number of threads configured for our CPU worker. */
unsigned int
cpuworker_get_n_threads(void)
{
  if (!threadpool) {
    return 0;
  }
  return threadpool_get_n_threads(threadpool);
}


static workqueue_reply_t
update_state_threadfn(void *state_, void *work_)
{
  worker_state_t *state = state_;
  worker_state_t *update = work_;
  server_onion_keys_free(state->onion_keys);
  state->onion_keys = update->onion_keys;
  update->onion_keys = NULL;
  worker_state_free(update);
  ++state->generation;
  return WQ_RPL_REPLY;
}

/** Called when the onion key has changed so update all CPU worker(s) with
 * new function pointers with which a new state will be generated.
 */
void
cpuworkers_rotate_keyinfo(void)
{
  if (!threadpool) {
    /* If we're a client, then we won't have cpuworkers, and we won't need
     * to tell them to rotate their state.
     */
    return;
  }
  if (threadpool_queue_update(threadpool,
                              worker_state_new,
                              update_state_threadfn,
                              worker_state_free_void,
                              NULL)) {
    log_warn(LD_OR, "Failed to queue key update for worker threads.");
  }
}

/** Indexed by handshake type: how many onionskins have we processed and
 * counted of that type? */
static uint64_t onionskins_n_processed[MAX_ONION_HANDSHAKE_TYPE+1];
/** Indexed by handshake type, corresponding to the onionskins counted in
 * onionskins_n_processed: how many microseconds have we spent in cpuworkers
 * processing that kind of onionskin? */
static uint64_t onionskins_usec_internal[MAX_ONION_HANDSHAKE_TYPE+1];
/** Indexed by handshake type, corresponding to onionskins counted in
 * onionskins_n_processed: how many microseconds have we spent waiting for
 * cpuworkers to give us answers for that kind of onionskin?
 */
static uint64_t onionskins_usec_roundtrip[MAX_ONION_HANDSHAKE_TYPE+1];

/** If any onionskin takes longer than this, we clip them to this
 * time. (microseconds) */
#define MAX_BELIEVABLE_ONIONSKIN_DELAY (2*1000*1000)

/** Return true iff we'd like to measure a handshake of type
 * <b>onionskin_type</b>. Call only from the main thread. */
static int
should_time_request(uint16_t onionskin_type)
{
  /* If we've never heard of this type, we shouldn't even be here. */
  if (onionskin_type > MAX_ONION_HANDSHAKE_TYPE)
    return 0;
  /* Measure the first N handshakes of each type, to ensure we have a
   * sample */
  if (onionskins_n_processed[onionskin_type] < 4096)
    return 1;

  /** Otherwise, measure with P=1/128.  We avoid doing this for every
   * handshake, since the measurement itself can take a little time. */
  return crypto_fast_rng_one_in_n(get_thread_fast_rng(), 128);
}

/** Return an estimate of how many microseconds we will need for a single
 * cpuworker to process <b>n_requests</b> onionskins of type
 * <b>onionskin_type</b>. */
uint64_t
estimated_usec_for_onionskins(uint32_t n_requests, uint16_t onionskin_type)
{
  if (onionskin_type > MAX_ONION_HANDSHAKE_TYPE) /* should be impossible */
    return 1000 * (uint64_t)n_requests;
  if (PREDICT_UNLIKELY(onionskins_n_processed[onionskin_type] < 100)) {
    /* Until we have 100 data points, just assume everything takes 1 msec. */
    return 1000 * (uint64_t)n_requests;
  } else {
    /* This can't overflow: we'll never have more than 500000 onionskins
     * measured in onionskin_usec_internal, and they won't take anything near
     * 1 sec each, and we won't have anything like 1 million queued
     * onionskins.  But that's 5e5 * 1e6 * 1e6, which is still less than
     * UINT64_MAX. */
    return (onionskins_usec_internal[onionskin_type] * n_requests) /
      onionskins_n_processed[onionskin_type];
  }
}

/** Compute the absolute and relative overhead of using the cpuworker
 * framework for onionskins of type <b>onionskin_type</b>.*/
static int
get_overhead_for_onionskins(uint32_t *usec_out, double *frac_out,
                            uint16_t onionskin_type)
{
  uint64_t overhead;

  *usec_out = 0;
  *frac_out = 0.0;

  if (onionskin_type > MAX_ONION_HANDSHAKE_TYPE) /* should be impossible */
    return -1;
  if (onionskins_n_processed[onionskin_type] == 0 ||
      onionskins_usec_internal[onionskin_type] == 0 ||
      onionskins_usec_roundtrip[onionskin_type] == 0)
    return -1;

  overhead = onionskins_usec_roundtrip[onionskin_type] -
    onionskins_usec_internal[onionskin_type];

  *usec_out = (uint32_t)(overhead / onionskins_n_processed[onionskin_type]);
  *frac_out = ((double)overhead) / onionskins_usec_internal[onionskin_type];

  return 0;
}

/** If we've measured overhead for onionskins of type <b>onionskin_type</b>,
 * log it. */
void
cpuworker_log_onionskin_overhead(int severity, int onionskin_type,
                                 const char *onionskin_type_name)
{
  uint32_t overhead;
  double relative_overhead;
  int r;

  r = get_overhead_for_onionskins(&overhead,  &relative_overhead,
                                  onionskin_type);
  if (!overhead || r<0)
    return;

  log_fn(severity, LD_OR,
         "%s onionskins have averaged %u usec overhead (%.2f%%) in "
         "cpuworker code ",
         onionskin_type_name, (unsigned)overhead, relative_overhead*100);
}

/** Handle a reply from the worker threads. */
STATIC void
cpuworker_onion_handshake_replyfn(void *work_)
{
  cpuworker_job_t *job = work_;
  cpuworker_reply_t rpl;
  or_circuit_t *circ = NULL;

  tor_assert(total_pending_tasks > 0);
  --total_pending_tasks;

  /* Could avoid this, but doesn't matter. */
  memcpy(&rpl, &job->u.reply, sizeof(rpl));
  circ=job->circ;
  payment_work_t *payment_work=job->payment_work;
  if (payment_work && circ->base_.magic!=DEAD_CIRCUIT_MAGIC)
    circ->payment_native_work=NULL;
  /* Actual work has ended. Preserve the copied reply while retiring the job
   * buffers before releasing the shared running/memory reservation. */
  memwipe(job,0,sizeof(*job)); tor_free(job);
  if (payment_work && !payment_work_result_timely(payment_work)) rpl.success=0;

  tor_assert(rpl.magic == CPUWORKER_REPLY_MAGIC);

  if (rpl.timed && rpl.success &&
      rpl.handshake_type <= MAX_ONION_HANDSHAKE_TYPE) {
    /* Time how long this request took. The handshake_type check should be
       needless, but let's leave it in to be safe. */
    struct timeval tv_end, tv_diff;
    int64_t usec_roundtrip;
    tor_gettimeofday(&tv_end);
    timersub(&tv_end, &rpl.started_at, &tv_diff);
    usec_roundtrip = ((int64_t)tv_diff.tv_sec)*1000000 + tv_diff.tv_usec;
    if (usec_roundtrip >= 0 &&
        usec_roundtrip < MAX_BELIEVABLE_ONIONSKIN_DELAY) {
      ++onionskins_n_processed[rpl.handshake_type];
      onionskins_usec_internal[rpl.handshake_type] += rpl.n_usec;
      onionskins_usec_roundtrip[rpl.handshake_type] += usec_roundtrip;
      if (onionskins_n_processed[rpl.handshake_type] >= 500000) {
        /* Scale down every 500000 handshakes.  On a busy server, that's
         * less impressive than it sounds. */
        onionskins_n_processed[rpl.handshake_type] /= 2;
        onionskins_usec_internal[rpl.handshake_type] /= 2;
        onionskins_usec_roundtrip[rpl.handshake_type] /= 2;
      }
    }
  }

  log_debug(LD_OR,
            "Unpacking cpuworker reply, circ=%p, success=%d",circ,rpl.success);

  if (circ->base_.magic == DEAD_CIRCUIT_MAGIC) {
    /* The circuit was supposed to get freed while the reply was
     * pending. Instead, it got left for us to free so that we wouldn't freak
     * out when the job->circ field wound up pointing to nothing. */
    log_debug(LD_OR, "Circuit died while reply was pending. Freeing memory.");
    circ->base_.magic = 0;
    tor_free(circ);
    goto done_processing;
  }

  circ->workqueue_entry = NULL;

  if (TO_CIRCUIT(circ)->marked_for_close) {
    /* We already marked this circuit; we can't call it open. */
    log_debug(LD_OR,"circuit is already marked.");
    goto done_processing;
  }

  if (rpl.success == 0) {
    log_debug(LD_OR,
              "decoding onionskin failed. "
              "(Old key or bad software.) Closing.");
    circuit_mark_for_close(TO_CIRCUIT(circ), END_CIRC_REASON_TORPROTOCOL);
    goto done_processing;
  }

  /* If the client asked for congestion control, if our consensus parameter
   * allowed it to negotiate as enabled, allocate a congestion control obj. */
  if (rpl.circ_params.cc_enabled) {
    if (get_options()->SbwsExit) {
      TO_CIRCUIT(circ)->ccontrol = congestion_control_new(&rpl.circ_params,
                                                          CC_PATH_SBWS);
    } else {
      TO_CIRCUIT(circ)->ccontrol = congestion_control_new(&rpl.circ_params,
                                                          CC_PATH_EXIT);
    }
  }

  circ->relay_cell_format = rpl.circ_params.cell_fmt;

  /* Authenticated negotiation cannot outrun the main-loop reservation. Install
   * all live owners before onionskin_answer queues the CREATED acknowledgement. */
  if (rpl.circ_params.eltor_resource_admitted) {
    if (!circ->payment_construction_prepared || !rpl.initial_material.valid ||
        !rpl.payment_result.valid ||
        free_capacity_circuit_confirm(TO_CIRCUIT(circ)) < 0) {
      circuit_mark_for_close(TO_CIRCUIT(circ),END_CIRC_REASON_RESOURCELIMIT);
      goto done_processing;
    }
    circ->payment_export_requested=true;
  } else {
    /* Missing negotiation is permitted only as a bounded directory endpoint.
     * It must never lose its reservation and become an unrestricted circuit. */
    if (circ->payment_construction_prepared &&
        free_capacity_circuit_confirm_bootstrap(TO_CIRCUIT(circ)) < 0) {
      circuit_mark_for_close(TO_CIRCUIT(circ), END_CIRC_REASON_RESOURCELIMIT);
      goto done_processing;
    }
    circ->payment_export_requested=false;
  }
  if (payment_profile_export_take(&circ->payment_keys,&rpl.payment_result,
                                    circ->payment_export_requested) < 0) {
    circuit_mark_for_close(TO_CIRCUIT(circ),END_CIRC_REASON_INTERNAL);
    goto done_processing;
  }
  if (rpl.circ_params.eltor_resource_admitted && circ->payment_policy_available &&
      payment_circuit_attach(circ,&circ->payment_construction_policy,
          rpl.initial_material.ids,rpl.initial_material.fee_hash,
          circ->payment_constructed_ms,monotime_absolute_msec()) != PAYMENT_CIRCUIT_OK) {
    circuit_mark_for_close(TO_CIRCUIT(circ),END_CIRC_REASON_RESOURCELIMIT);
    goto done_processing;
  }

  if (onionskin_answer(circ,
                       &rpl.created_cell,
                       rpl.circ_params.crypto_alg,
                       (const char*)rpl.keys, rpl.keys_len,
                       rpl.rend_auth_material) < 0) {
    log_warn(LD_OR,"onionskin_answer failed. Closing.");
    circuit_mark_for_close(TO_CIRCUIT(circ), END_CIRC_REASON_INTERNAL);
    goto done_processing;
  }


  log_debug(LD_OR,"onionskin_answer succeeded. Yay.");

 done_processing:
  memwipe(&rpl, 0, sizeof(rpl));
  queue_pending_tasks();
}

/** Implementation function for onion handshake requests. */
STATIC workqueue_reply_t
cpuworker_onion_handshake_threadfn(void *state_, void *work_)
{
  worker_state_t *state = state_;
  cpuworker_job_t *job = work_;

  /* variables for onion processing */
  server_onion_keys_t *onion_keys = state->onion_keys;
  cpuworker_request_t req;
  cpuworker_reply_t rpl;

  memcpy(&req, &job->u.request, sizeof(req));

  tor_assert(req.magic == CPUWORKER_REQUEST_MAGIC);
  memset(&rpl, 0, sizeof(rpl));

  const create_cell_t *cc = &req.create_cell;
  created_cell_t *cell_out = &rpl.created_cell;
  struct timeval tv_start = {0,0}, tv_end;
  int n;
  rpl.timed = req.timed;
  rpl.started_at = req.started_at;
  rpl.handshake_type = cc->handshake_type;
  if (req.timed)
    tor_gettimeofday(&tv_start);
  uint64_t circuit_id_64 = req.circuit_id;
  uint64_t n_circuit_id_64 = req.n_circuit_id;
  rpl.keys_len = sizeof(rpl.keys);
  uint64_t worker_now=monotime_absolute_msec();
  if (req.circ_ns_params.eltor_resource_eligible &&
      (worker_now<req.payment_native_queued_ms ||
       worker_now>=req.payment_native_start_before_ms)) {
    n=-1;
  } else n = onion_skin_server_handshake(cc->handshake_type,
                                  cc->onionskin, cc->handshake_len,
                                  onion_keys,
                                  &req.circ_ns_params,
                                  cell_out->reply,
                                  sizeof(cell_out->reply),
                                  rpl.keys, &rpl.keys_len,
                                  rpl.rend_auth_material,
                                  &rpl.circ_params,
                                  &circuit_id_64,
                                  &n_circuit_id_64,
                                  req.payment_export_requested,
                                  &rpl.payment_result, &rpl.initial_material);
  if (n < 0) {
    /* failure */
    log_debug(LD_OR,"onion_skin_server_handshake failed.");
    memwipe(&rpl, 0, sizeof(rpl));
    rpl.success = 0;
  } else {
    /* success */
    log_debug(LD_OR,"onion_skin_server_handshake succeeded.");
    cell_out->handshake_len = n;
    switch (cc->cell_type) {
    case CELL_CREATE:
      cell_out->cell_type = CELL_CREATED; break;
    case CELL_CREATE2:
      cell_out->cell_type = CELL_CREATED2; break;
    case CELL_CREATE_FAST:
      cell_out->cell_type = CELL_CREATED_FAST; break;
    default:
      tor_assert(0);
      return WQ_RPL_SHUTDOWN;
    }
    rpl.success = 1;
  }

  rpl.magic = CPUWORKER_REPLY_MAGIC;
  if (req.timed) {
    struct timeval tv_diff;
    int64_t usec;
    tor_gettimeofday(&tv_end);
    timersub(&tv_end, &tv_start, &tv_diff);
    usec = ((int64_t)tv_diff.tv_sec)*1000000 + tv_diff.tv_usec;
    if (usec < 0 || usec > MAX_BELIEVABLE_ONIONSKIN_DELAY)
      rpl.n_usec = MAX_BELIEVABLE_ONIONSKIN_DELAY;
    else
      rpl.n_usec = (uint32_t) usec;
  }

  memcpy(&job->u.reply, &rpl, sizeof(rpl));

  memwipe(&req, 0, sizeof(req));
  memwipe(&rpl, 0, sizeof(rpl));
  return WQ_RPL_REPLY;
}

/** Take pending tasks from the queue and assign them to cpuworkers. */
static void
queue_pending_tasks(void)
{
  or_circuit_t *circ;
  create_cell_t *onionskin = NULL;

  while (total_pending_tasks < max_pending_tasks) {
    circ = onion_next_task(&onionskin);

    if (!circ)
      return;

    if (assign_onionskin_to_cpuworker(circ, onionskin) < 0)
      log_info(LD_OR,"assign_to_cpuworker failed. Ignoring.");
  }
}

/** DOCDOC */
MOCK_IMPL(workqueue_entry_t *,
cpuworker_queue_work,(workqueue_priority_t priority,
                      workqueue_reply_t (*fn)(void *, void *),
                      void (*reply_fn)(void *),
                      void *arg))
{
  tor_assert(threadpool);

  return threadpool_queue_work_priority(threadpool,
                                        priority,
                                        fn,
                                        reply_fn,
                                        arg);
}

static void
cpuworker_payment_entry_released(void *arg)
{
  (void)payment_work_complete(arg);
}

static int
cpuworker_payment_start(payment_work_t *work, void *arg)
{
  cpuworker_job_t *job=arg;
  or_circuit_t *circ=job->circ;
  if (circ->base_.marked_for_close || total_pending_tasks>=max_pending_tasks)
    return -1;
  workqueue_entry_t *entry=cpuworker_queue_work(WQ_PRI_HIGH,
      cpuworker_onion_handshake_threadfn,cpuworker_onion_handshake_replyfn,job);
  if (!entry) return -1;
  workqueue_entry_set_reply_release(entry,cpuworker_payment_entry_released,work);
  job->payment_work=work;
  ++total_pending_tasks;
  circ->workqueue_entry=entry;
  return 0;
}

static void
cpuworker_payment_drop(void *arg)
{
  cpuworker_job_t *job=arg;
  or_circuit_t *circ=job->circ;
  circ->payment_native_work=NULL;
  memwipe(job,0,sizeof(*job)); tor_free(job);
  if (!circ->base_.marked_for_close)
    circuit_mark_for_close(TO_CIRCUIT(circ),END_CIRC_REASON_RESOURCELIMIT);
}

/** Try to tell a cpuworker to perform the public key operations necessary to
 * respond to <b>onionskin</b> for the circuit <b>circ</b>.
 *
 * Return 0 if we successfully assign the task, or -1 on failure.
 */
int
assign_onionskin_to_cpuworker(or_circuit_t *circ,
                              create_cell_t *onionskin)
{
  workqueue_entry_t *queue_entry;
  cpuworker_job_t *job;
  cpuworker_request_t req;
  int should_time;

  tor_assert(threadpool);

  if (!circ->p_chan) {
    log_info(LD_OR,"circ->p_chan gone. Failing circ.");
    tor_free(onionskin);
    return -1;
  }

  /* Every accepted handshake in enabled mode shares setup admission, including
   * directory bootstrap. No handshake type creates a legacy resource lane. */
  if (!circ->payment_construction_prepared) {
    payment_profile_policy_t policy;
    bool candidate;
    if (payment_circuit_construction_policy(&policy,&candidate)) {
      if (free_capacity_circuit_prepare_channel(TO_CIRCUIT(circ),circ->p_chan) < 0 ||
          free_capacity_circuit_setup_received(TO_CIRCUIT(circ),circ->p_chan) < 0) {
        free_capacity_circuit_free(TO_CIRCUIT(circ));
        tor_free(onionskin);
        return -1;
      }
      circ->payment_construction_prepared=true;
      circ->payment_constructed_ms=monotime_absolute_msec();
      circ->payment_construction_policy=policy;
      circ->payment_policy_available=candidate;
    }
  }

  if (!circ->payment_construction_prepared &&
      total_pending_tasks >= max_pending_tasks) {
    log_debug(LD_OR,"No idle cpuworkers. Queuing.");
    if (onion_pending_add(circ, onionskin) < 0) {
      tor_free(onionskin);
      return -1;
    }
    return 0;
  }

  if (!channel_is_client(circ->p_chan))
    rep_hist_note_circuit_handshake_assigned(onionskin->handshake_type);

  should_time = should_time_request(onionskin->handshake_type);
  memset(&req, 0, sizeof(req));
  req.magic = CPUWORKER_REQUEST_MAGIC;
  req.timed = should_time;

  memcpy(&req.create_cell, onionskin, sizeof(create_cell_t));

  tor_free(onionskin);

  if (should_time)
    tor_gettimeofday(&req.started_at);

  /* Copy the current cached consensus params relevant to
   * circuit negotiation into the CPU worker context */
  req.circ_ns_params.cc_enabled = congestion_control_enabled();
  req.circ_ns_params.sendme_inc_cells = congestion_control_sendme_inc();

  /* Copy the circuit ID for payment processing */
  req.circ_ns_params.eltor_resource_eligible=circ->payment_construction_prepared;
  req.payment_export_requested=circ->payment_construction_prepared &&
    req.create_cell.handshake_type == ONION_HANDSHAKE_TYPE_NTOR_V3;
  if (circ->payment_construction_prepared) {
    req.payment_native_queued_ms=monotime_absolute_msec();
    uint64_t wait=payment_resources_protocol()->limits.max_wait_ms;
    req.payment_native_start_before_ms=req.payment_native_queued_ms>UINT64_MAX-wait ?
      UINT64_MAX : req.payment_native_queued_ms+wait;
  }
  req.circuit_id = circ->p_circ_id;
  req.n_circuit_id = TO_CIRCUIT(circ)->n_circ_id;

  payment_work_t *payment_work=NULL;
  if (circ->payment_construction_prepared) {
    uint64_t lifetime=circ->payment_policy_available ?
      circ->payment_construction_policy.setup_timeout_ms : FREE_CAPACITY_LIFETIME_MS;
    if (circ->payment_constructed_ms>UINT64_MAX-lifetime ||
        !(payment_work=payment_work_reserve(NULL,PROTOCOL_BUDGET_NATIVE_SETUP,
            /* The native callback may outlive circuit teardown: DEAD_CIRCUIT
             * storage remains allocated until its actual reply frees it. */
            sizeof(cpuworker_job_t)+workqueue_entry_memory_cost()+sizeof(*circ),
            circ->payment_constructed_ms+lifetime))) {
      memwipe(&req,0,sizeof(req));
      return -1;
    }
  }
  job = tor_malloc_zero(sizeof(cpuworker_job_t));
  job->circ = circ;
  memcpy(&job->u.request, &req, sizeof(req));
  memwipe(&req, 0, sizeof(req));

  if (payment_work) {
    job->payment_work=payment_work;
    circ->payment_native_work=payment_work;
    if (payment_work_queue(payment_work,cpuworker_payment_start,
                             cpuworker_payment_drop,job)<0) {
      circ->payment_native_work=NULL;
      memwipe(job,0,sizeof(*job)); tor_free(job);
      payment_work_release(payment_work);
      return -1;
    }
    return 0;
  }

  queue_entry = cpuworker_queue_work(WQ_PRI_HIGH,
                                      cpuworker_onion_handshake_threadfn,
                                      cpuworker_onion_handshake_replyfn,
                                      job);
  if (!queue_entry) {
    log_warn(LD_BUG, "Couldn't queue work on threadpool");
    memwipe(job,0,sizeof(*job)); tor_free(job);
    return -1;
  }
  ++total_pending_tasks;

  log_debug(LD_OR, "Queued task %p (qe=%p, circ=%p)",
            job, queue_entry, job->circ);

  circ->workqueue_entry = queue_entry;

  return 0;
}

/** If <b>circ</b> has a pending handshake that hasn't been processed yet,
 * remove it from the worker queue. */
void
cpuworker_cancel_circ_handshake(or_circuit_t *circ)
{
  cpuworker_job_t *job;
  if (circ->payment_native_work && !circ->workqueue_entry &&
      payment_work_cancel(circ->payment_native_work)) return;
  if (circ->workqueue_entry == NULL)
    return;

  job = workqueue_entry_cancel(circ->workqueue_entry);
  if (job) {
    /* It successfully cancelled. */
    payment_work_t *payment_work=job->payment_work;
    circ->payment_native_work=NULL;
    memwipe(job, 0xe0, sizeof(*job));
    tor_free(job);
    tor_assert(total_pending_tasks > 0);
    --total_pending_tasks;
    /* if (!job), this is done in cpuworker_onion_handshake_replyfn. */
    circ->workqueue_entry = NULL;
    if (payment_work) (void)payment_work_complete(payment_work);
  }
}
