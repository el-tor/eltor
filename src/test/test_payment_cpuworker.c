/* Copyright (c) 2026, The El Tor Project. */
/* See LICENSE for licensing information. */
#define RELAY_PRIVATE
#define CPUWORKER_PRIVATE
#define CHANNEL_OBJECT_PRIVATE
#define TOR_CONGESTION_CONTROL_PRIVATE
#define TOR_CONGESTION_CONTROL_COMMON_PRIVATE
#define CIRCUITMUX_EWMA_PRIVATE
#include "orconfig.h"
#include "core/or/or.h"
#include "core/mainloop/cpuworker.h"
#include "core/or/circuitlist.h"
#include "core/or/or_circuit_st.h"
#include "core/or/or_connection_st.h"
#include "core/or/channeltls.h"
#include "core/or/extend_info_st.h"
#include "core/or/cell_queue_st.h"
#include "core/or/circuitmux_ewma.h"
#include "core/or/congestion_control_st.h"
#include "core/or/congestion_control_common.h"
#include "core/or/scheduler.h"
#include "core/or/relay.h"
#include "feature/payment/payment_circuit.h"
#include "feature/payment/free_capacity_hooks.h"
#include "feature/payment/payment_resources.h"
#include "feature/control/control_payment.h"
#include "lib/crypt_ops/crypto_curve25519.h"
#include "lib/crypt_ops/crypto_util.h"
#include "lib/evloop/timers.h"
#include "lib/time/compat_time.h"
#include "test/fakechans.h"
#include "test/test.h"

/* The native queue is held deterministically at its thread boundary. The
 * captured callbacks are the actual CPU worker functions, not a replacement
 * crypto adapter. Lower workqueue tests exercise real pthread/reply delivery. */
static cpuworker_job_t *queued_job;
static workqueue_reply_t (*queued_fn)(void *,void *);
static void (*queued_reply)(void *);
static void (*entry_release)(void *);
static void *entry_release_arg;
static int queue_fail, cancel_running;
static char entry_storage;
static workqueue_entry_t *const fake_entry=(workqueue_entry_t *)&entry_storage;

static workqueue_entry_t *
capture_queue(workqueue_priority_t priority,
              workqueue_reply_t (*fn)(void *,void *),
              void (*reply)(void *),void *arg)
{
  (void)priority;
  if (queue_fail) return NULL;
  tor_assert(!queued_job);
  queued_job=arg; queued_fn=fn; queued_reply=reply;
  return fake_entry;
}
static void
capture_release(workqueue_entry_t *entry,void (*fn)(void *),void *arg)
{
  tor_assert(entry==fake_entry);
  entry_release=fn; entry_release_arg=arg;
}
static void *
capture_cancel(workqueue_entry_t *entry)
{
  tor_assert(entry==fake_entry);
  if (cancel_running) return NULL;
  cpuworker_job_t *job=queued_job;
  queued_job=NULL; queued_fn=NULL; queued_reply=NULL;
  entry_release=NULL; entry_release_arg=NULL;
  return job;
}
static void
native_reply(void)
{
  cpuworker_job_t *job=queued_job;
  void (*reply)(void *)=queued_reply;
  void (*release)(void *)=entry_release;
  void *release_arg=entry_release_arg;
  queued_job=NULL; queued_fn=NULL; queued_reply=NULL;
  entry_release=NULL; entry_release_arg=NULL;
  reply(job);
  /* Actual workqueue destroys its entry between these two callbacks. */
  tor_assert(payment_resources_protocol()->running==1);
  release(release_arg);
}

static const char *
initial_payload(void)
{
  static char payload[782];
  memcpy(payload,"eltor_payhash",13);
  memset(payload+13,'0',768); payload[781]=0;
  for (unsigned i=0;i<10;++i) payload[13+128+i*64+63]="123456789a"[i];
  return payload;
}

typedef struct cpu_fixture_t {
  channel_tls_t *chan;
  or_connection_t conn;
  or_circuit_t *circ;
  curve25519_keypair_t relay_key;
  server_onion_keys_t keys;
  extend_info_t info;
  onion_handshake_state_t client;
  create_cell_t create;
} cpu_fixture_t;
static void
cpu_init(void)
{
  monotime_enable_test_mocking();
  monotime_set_mock_time_nsec(INT64_C(1000000000));
  monotime_coarse_set_mock_time_nsec(INT64_C(1000000000));
  timers_initialize(); cell_ewma_initialize_ticks();
  congestion_control_set_cc_disabled();
  MOCK(cpuworker_queue_work,capture_queue);
  MOCK(workqueue_entry_set_reply_release,capture_release);
  MOCK(workqueue_entry_cancel,capture_cancel);
  MOCK(scheduler_channel_has_waiting_cells,
       scheduler_channel_has_waiting_cells_mock);
  MOCK(scheduler_release_channel,scheduler_release_channel_mock);
  threadpool=(threadpool_t *)&entry_storage;
  queued_job=NULL; entry_release=NULL; total_pending_tasks=0;
  queue_fail=cancel_running=0;
}
static int
cpu_fixture(cpu_fixture_t *f)
{
  memset(f,0,sizeof(*f));
  f->chan=tor_realloc(new_fake_channel(),sizeof(*f->chan));
  f->chan->base_.magic=TLS_CHAN_MAGIC;
  f->chan->base_.wide_circ_ids=true;
  f->chan->base_.is_client=true;
  f->chan->base_.is_local=true;
  f->chan->conn=&f->conn;
  f->conn.wide_circ_ids=true; f->conn.chan=f->chan;
  f->circ=or_circuit_new(10,&f->chan->base_);
  f->circ->base_.purpose=CIRCUIT_PURPOSE_OR;
  f->circ->base_.state=CIRCUIT_STATE_ONIONSKIN_PENDING;
  if (free_capacity_circuit_prepare(TO_CIRCUIT(f->circ),&f->conn)<0) return -1;
  f->circ->payment_construction_prepared=true;
  f->circ->payment_constructed_ms=1000;
  if (curve25519_keypair_generate(&f->relay_key,0)<0) return -1;
  memset(f->info.ed_identity.pubkey,0x5c,32);
  f->info.curve25519_onion_key=f->relay_key.pubkey;
  f->info.supports_ntor_v3=f->info.payment_free_v1=true;
  f->keys.my_ed_identity=f->info.ed_identity;
  f->keys.junk_keypair=&f->relay_key;
  dimap_add_entry(&f->keys.curve25519_key_map,
                 f->relay_key.pubkey.public_key,&f->relay_key);
  f->create.cell_type=CELL_CREATE2;
  f->create.handshake_type=ONION_HANDSHAKE_TYPE_NTOR_V3;
  int n=onion_skin_create(ONION_HANDSHAKE_TYPE_NTOR_V3,&f->info,&f->client,
             f->create.onionskin,sizeof(f->create.onionskin),initial_payload(),true);
  if (n<0) return -1;
  f->create.handshake_len=n;
  return 0;
}
static int
cpu_assign(cpu_fixture_t *f)
{
  create_cell_t *create=tor_memdup(&f->create,sizeof(f->create));
  return assign_onionskin_to_cpuworker(f->circ,create);
}
static void
cpu_cleanup(cpu_fixture_t *f)
{
  if (queued_job) {
    queued_job->u.reply=(cpuworker_reply_t){.magic=CPUWORKER_REPLY_MAGIC};
    native_reply();
  }
  circuit_free_all();
  free_capacity_connection_free(&f->conn);
  f->conn.chan=NULL;
  if (f->chan) free_fake_channel(&f->chan->base_);
  dimap_free(f->keys.curve25519_key_map,NULL);
  onion_handshake_state_release(&f->client);
  control_payment_free_all();
  (void)payment_workqueue_free_all();
  (void)payment_resources_free_all();
  threadpool=NULL; timers_shutdown(); monotime_disable_test_mocking();
  UNMOCK(cpuworker_queue_work);
  UNMOCK(workqueue_entry_set_reply_release); UNMOCK(workqueue_entry_cancel);
  UNMOCK(scheduler_channel_has_waiting_cells); UNMOCK(scheduler_release_channel);
}

static void
test_cpu_authenticated_install(void *arg)
{
  cpu_fixture_t f={0}; (void)arg;
  payment_profile_export_t client_export={0};
  circuit_params_t params;
  uint8_t traffic[MAX_RELAY_KEY_MATERIAL_LEN], nonce[DIGEST_LEN];
  size_t len=sizeof(traffic);
  cpu_init(); tt_int_op(cpu_fixture(&f),OP_EQ,0);
  tt_int_op(cpu_assign(&f),OP_EQ,0);
  tt_uint_op(total_pending_tasks,OP_EQ,1);
  tt_uint_op(payment_resources_protocol()->running,OP_EQ,1);
  worker_state_t state={.onion_keys=&f.keys};
  tt_int_op(queued_fn(&state,queued_job),OP_EQ,WQ_RPL_REPLY);
  tt_int_op(queued_job->u.reply.success,OP_EQ,1);
  tt_assert(queued_job->u.reply.payment_result.valid);
  tt_assert(queued_job->u.reply.initial_material.valid);
  tt_int_op(onion_skin_client_handshake(ONION_HANDSHAKE_TYPE_NTOR_V3,&f.client,
      queued_job->u.reply.created_cell.reply,
      queued_job->u.reply.created_cell.handshake_len,traffic,&len,nonce,&params,
      NULL,&client_export),OP_EQ,0);
  tt_mem_op(traffic,OP_EQ,queued_job->u.reply.keys,len);
  tt_mem_op(&client_export.keys,OP_EQ,&queued_job->u.reply.payment_result.keys,
             sizeof(client_export.keys));
  native_reply();
  tt_uint_op(total_pending_tasks,OP_EQ,0);
  tt_uint_op(payment_resources_protocol()->running,OP_EQ,0);
  tt_assert(!f.circ->base_.marked_for_close);
  tt_assert(f.circ->payment_keys);
  tt_mem_op(f.circ->payment_keys,OP_EQ,&client_export.keys,sizeof(client_export.keys));
  tt_ptr_op(f.circ->payment_native_work,OP_EQ,NULL);
  tt_uint_op(f.circ->p_chan_cells.n,OP_EQ,1); /* CREATED only after owners exist. */
 done:
  payment_profile_export_clear(&client_export); cpu_cleanup(&f);
}

static void
test_cpu_native_deadline(void *arg)
{
  cpu_fixture_t f={0}; (void)arg;
  cpu_init(); tt_int_op(cpu_fixture(&f),OP_EQ,0);
  tt_int_op(cpu_assign(&f),OP_EQ,0);
  /* Missing keys would crash if the expensive primitive were entered. The
   * immutable original deadline is checked in the real worker callback. */
  worker_state_t state={0};
  monotime_set_mock_time_nsec(INT64_C(2000000000));
  tt_int_op(queued_fn(&state,queued_job),OP_EQ,WQ_RPL_REPLY);
  cpuworker_reply_t zero={.magic=CPUWORKER_REPLY_MAGIC};
  tt_mem_op(&queued_job->u.reply,OP_EQ,&zero,sizeof(zero));
  native_reply();
  tt_assert(f.circ->base_.marked_for_close);
  tt_ptr_op(f.circ->payment_keys,OP_EQ,NULL);
  tt_uint_op(f.circ->p_chan_cells.n,OP_EQ,0);
  tt_uint_op(total_pending_tasks,OP_EQ,0);
  tt_uint_op(payment_resources_protocol()->running,OP_EQ,0);
 done:
  cpu_cleanup(&f);
}

static void
test_cpu_cancel_and_queue_failure(void *arg)
{
  cpu_fixture_t f={0}; (void)arg;
  cpu_init(); tt_int_op(cpu_fixture(&f),OP_EQ,0);
  uint32_t baseline=payment_resources_protocol()->arena_used;
  queue_fail=1;
  tt_int_op(cpu_assign(&f),OP_EQ,0); /* accepted shared job, failed native start */
  tt_assert(f.circ->base_.marked_for_close);
  tt_uint_op(total_pending_tasks,OP_EQ,0);
  tt_uint_op(payment_resources_protocol()->running,OP_EQ,0);
  tt_int_op(payment_workqueue_free_all(),OP_EQ,0);
  tt_uint_op(payment_resources_protocol()->arena_used,OP_EQ,baseline);
 done:
  cpu_cleanup(&f);
}

static void
test_cpu_running_circuit_death(void *arg)
{
  cpu_fixture_t f={0}; (void)arg;
  cpu_init(); tt_int_op(cpu_fixture(&f),OP_EQ,0);
  tt_int_op(cpu_assign(&f),OP_EQ,0);
  cancel_running=1;
  circuit_free_all(); f.circ=NULL;
  tt_uint_op(queued_job->circ->base_.magic,OP_EQ,DEAD_CIRCUIT_MAGIC);
  tt_uint_op(total_pending_tasks,OP_EQ,1);
  tt_uint_op(payment_resources_protocol()->running,OP_EQ,1);
  queued_job->u.reply=(cpuworker_reply_t){.magic=CPUWORKER_REPLY_MAGIC};
  native_reply();
  tt_uint_op(total_pending_tasks,OP_EQ,0);
  tt_uint_op(payment_resources_protocol()->running,OP_EQ,0);
 done:
  cpu_cleanup(&f);
}

static void
test_cpu_native_cancel(void *arg)
{
  cpu_fixture_t f={0}; (void)arg;
  cpu_init(); tt_int_op(cpu_fixture(&f),OP_EQ,0);
  uint32_t baseline=payment_resources_protocol()->arena_used;
  tt_int_op(cpu_assign(&f),OP_EQ,0);
  cpuworker_cancel_circ_handshake(f.circ);
  tt_ptr_op(queued_job,OP_EQ,NULL);
  tt_ptr_op(f.circ->payment_native_work,OP_EQ,NULL);
  tt_ptr_op(f.circ->workqueue_entry,OP_EQ,NULL);
  tt_uint_op(total_pending_tasks,OP_EQ,0);
  tt_uint_op(payment_resources_protocol()->running,OP_EQ,0);
  tt_int_op(payment_workqueue_free_all(),OP_EQ,0);
  tt_uint_op(payment_resources_protocol()->arena_used,OP_EQ,baseline);
 done:
  cpu_cleanup(&f);
}
/* Exercise actual CPU request/reply dispatch for each nonnegotiated handshake,
 * not merely the token bucket. None may open an unrestricted relay circuit. */
static void
test_cpu_bounded_bootstrap(void *arg)
{
  (void)arg;
  const unsigned types[] = { ONION_HANDSHAKE_TYPE_FAST,
    ONION_HANDSHAKE_TYPE_NTOR, ONION_HANDSHAKE_TYPE_NTOR_V3 };
  for (unsigned i = 0; i < ARRAY_LENGTH(types); ++i) {
    cpu_fixture_t f = {0};
    cpu_init();
    tt_int_op(cpu_fixture(&f), OP_EQ, 0);
    payment_profile_policy_t policy = payment_profile_testing_policy();
    tt_int_op(payment_circuit_configure_construction(true, &policy), OP_EQ, 0);
    /* Remove the fixture's prepared admission: real dispatch must reserve it. */
    free_capacity_circuit_free(TO_CIRCUIT(f.circ));
    f.circ->payment_construction_prepared = false;
    onion_handshake_state_release(&f.client);
    memset(&f.client, 0, sizeof(f.client));
    f.create.cell_type = types[i] == ONION_HANDSHAKE_TYPE_FAST ?
      CELL_CREATE_FAST : CELL_CREATE2;
    f.create.handshake_type = types[i];
    int n = onion_skin_create(types[i], &f.info, &f.client, f.create.onionskin,
                               sizeof(f.create.onionskin), NULL, false);
    tt_int_op(n, OP_GT, 0);
    f.create.handshake_len = n;
    tt_int_op(cpu_assign(&f), OP_EQ, 0);
    tt_uint_op(payment_resources_free()->live_circuits, OP_EQ, 1);
    tt_uint_op(payment_resources_protocol()->running, OP_EQ, 1);
    tt_assert(!free_capacity_circuit_is_normal(TO_CIRCUIT(f.circ)));
    worker_state_t state = {.onion_keys = &f.keys};
    tt_int_op(queued_fn(&state, queued_job), OP_EQ, WQ_RPL_REPLY);
    tt_int_op(queued_job->u.reply.success, OP_EQ, 1);
    tt_assert(!queued_job->u.reply.circ_params.eltor_resource_admitted);
    native_reply();
    tt_assert(!f.circ->base_.marked_for_close);
    tt_assert(free_capacity_circuit_is_bootstrap(TO_CIRCUIT(f.circ)));
    tt_assert(!free_capacity_circuit_is_normal(TO_CIRCUIT(f.circ)));
    tt_assert(!free_capacity_circuit_ready(TO_CIRCUIT(f.circ), 1000));
    tt_assert(!f.circ->payment_export_requested);
    tt_ptr_op(f.circ->payment_keys, OP_EQ, NULL);
    tt_ptr_op(f.circ->payment_profile, OP_EQ, NULL);
    tt_uint_op(payment_resources_free()->live_circuits, OP_EQ, 1);
    tt_uint_op(payment_resources_protocol()->running, OP_EQ, 0);
    tt_u64_op(payment_resources_protocol()->attempts_started, OP_EQ, 1);
    tt_assert(free_capacity_bootstrap_command_allowed(TO_CIRCUIT(f.circ),
      RELAY_COMMAND_BEGIN_DIR, 1, false));
    tt_assert(free_capacity_bootstrap_command_allowed(TO_CIRCUIT(f.circ),
      RELAY_COMMAND_DATA, 1, true));
    tt_assert(!free_capacity_bootstrap_command_allowed(TO_CIRCUIT(f.circ),
      RELAY_COMMAND_DATA, 1, false));
    const uint8_t forbidden[] = { RELAY_COMMAND_BEGIN, RELAY_COMMAND_RESOLVE,
      RELAY_COMMAND_EXTEND2, RELAY_COMMAND_ESTABLISH_INTRO,
      RELAY_COMMAND_ESTABLISH_RENDEZVOUS, RELAY_COMMAND_PAYMENT_COMMIT };
    for (unsigned j = 0; j < ARRAY_LENGTH(forbidden); ++j) {
      relay_msg_t msg = {.command = forbidden[j], .stream_id = 1};
      tt_int_op(handle_relay_msg(&msg, TO_CIRCUIT(f.circ), NULL, NULL, 0),
                OP_EQ, -END_CIRC_REASON_TORPROTOCOL);
    }
    /* Switching to paid never clears the immutable bootstrap restriction. */
    free_capacity_circuit_paid(TO_CIRCUIT(f.circ));
    tt_assert(free_capacity_circuit_is_bootstrap(TO_CIRCUIT(f.circ)));
    /* The original CREATE plus both directions shares the128-cell burst. */
    for (unsigned j = 0; j < 127; ++j) {
      if (j % 2) {
        tt_assert(free_capacity_wire_receive(&f.conn, 10, 2053, true, CELL_RELAY));
      } else {
        tt_int_op(free_capacity_circuit_send(TO_CIRCUIT(f.circ),
                    &f.chan->base_), OP_EQ, FREE_CAPACITY_OK);
      }
    }
    tt_int_op(free_capacity_circuit_send(TO_CIRCUIT(f.circ), &f.chan->base_),
              OP_EQ, FREE_CAPACITY_WAIT);
    cpu_cleanup(&f);
    continue;
 done:
    cpu_cleanup(&f);
    return;
  }
}

#define CPU_TEST(name) {#name,test_cpu_##name,TT_FORK,NULL,NULL}
struct testcase_t payment_cpuworker_tests[]={
  CPU_TEST(authenticated_install), CPU_TEST(native_deadline),
  CPU_TEST(cancel_and_queue_failure), CPU_TEST(running_circuit_death),
  CPU_TEST(native_cancel), CPU_TEST(bounded_bootstrap), END_OF_TESTCASES
};
