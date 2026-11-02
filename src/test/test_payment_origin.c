/* Copyright (c) 2026, The El Tor Project. */
/* See LICENSE for licensing information. */
#define CHANNEL_OBJECT_PRIVATE
#define CIRCUITMUX_EWMA_PRIVATE
#define SELFTEST_PRIVATE
#include "orconfig.h"
#include "core/or/or.h"
#include "core/or/origin_circuit_st.h"
#include "core/or/or_connection_st.h"
#include "core/or/channeltls.h"
#include "core/or/cell_queue_st.h"
#include "core/or/cell_st.h"
#include "core/or/circuitmux.h"
#include "core/or/circuitmux_ewma.h"
#include "core/or/scheduler.h"
#include "test/fakechans.h"
#include "core/or/crypt_path_st.h"
#include "core/or/cpath_build_state_st.h"
#include "core/or/extend_info_st.h"
#include "core/or/relay_msg_st.h"
#include "core/or/circuitlist.h"
#include "core/or/circuituse.h"
#include "core/or/entry_connection_st.h"
#include "core/or/connection_edge.h"
#include "core/or/socks_request_st.h"
#include "core/or/crypt_path.h"
#include "core/or/relay.h"
#include "core/crypto/relay_crypto.h"
#include "feature/payment/payment_origin.h"
#include "feature/payment/payment_resources.h"
#include "feature/payment/payment_workqueue.h"
#include "core/crypto/onion_crypto.h"
#include "core/crypto/onion_fast.h"
#include "core/or/onion.h"
#include "feature/payment/free_capacity_hooks.h"
#include "feature/payment/payment_util.h"
#include "feature/payment/payment_initial.h"
#include "lib/crypt_ops/crypto_digest.h"
#include "feature/control/control_payment.h"
#include "feature/control/control.h"
#include "feature/relay/selftest.h"
#include "feature/nodelist/routerinfo_st.h"
#include "core/or/extendinfo.h"
#include "core/mainloop/connection.h"
#include "feature/control/control_proto.h"
#include "feature/control/control_connection_st.h"
#include "lib/evloop/timers.h"
#include "lib/time/compat_time.h"
#include "test/test.h"
#include "test/test_helpers.h"

static uint8_t sent_wire[PAYMENT_PROFILE_WIRE_LEN];
static uint8_t sent_command;
static unsigned sent_count;
static smartlist_t *replies;

static int
capture_origin(streamid_t stream, circuit_t *circ, uint8_t command,
               const char *payload, size_t len, crypt_path_t *layer,
               const char *file, int line)
{
  (void)circ; (void)file; (void)line;
  if (stream || !layer || len != sizeof(sent_wire)) return -1;
  memcpy(sent_wire,payload,len); sent_command=command; ++sent_count;
  return 0;
}

static void
capture_control(control_connection_t *conn, int code, int separator,
                const char *text)
{
  (void)conn;
  char *line;
  tor_asprintf(&line,"%d%c%s\r\n",code,separator,text);
  smartlist_add(replies,line);
}

typedef struct origin_fixture_t {
  origin_circuit_t *circ;
  crypt_path_t *hop;
  payment_profile_policy_t policy;
  uint8_t policy_wire[55], ids[10][32], q[32], a0[32];
  payment_profile_keys_t keys;
  char payload[782];
} origin_fixture_t;

static int
init_origin_policy(origin_fixture_t *f, bool final)
{
  memset(f,0,sizeof(*f));
  timers_initialize();
  monotime_enable_test_mocking();
  monotime_set_mock_time_nsec(INT64_C(1000000000));
  monotime_coarse_set_mock_time_nsec(INT64_C(1000000000));
  MOCK(relay_send_command_from_edge_,capture_origin);
  f->policy.rate_msat=1000; f->policy.initial_handshake_fee_msat=10;
  f->policy.grace_ms=15000; f->policy.max_age_ms=1800000;
  f->policy.max_periods=final?2:3; f->policy.setup_timeout_ms=30000;
  if (final) f->policy.max_age_ms=600000;
  if (payment_profile_policy_encode(f->policy_wire,55,&f->policy)) return -1;
  extend_info_t info={0};
  info.supports_ntor_v3=info.payment_start_v1=info.payment_renew_v1=true;
  info.payment_free_v1=true;
  memcpy(info.payment_profile_terms,f->policy_wire,55);
  f->circ=origin_circuit_new();
  f->circ->base_.purpose=CIRCUIT_PURPOSE_CONTROLLER;
  f->circ->build_state=tor_malloc_zero(sizeof(*f->circ->build_state));
  f->circ->build_state->desired_path_len=1;
  f->circ->any_hop_from_controller=1;
  if (cpath_append_hop(&f->circ->cpath,&info)) return -1;
  f->hop=f->circ->cpath;
  memset(f->keys.binding,0x11,32); memset(f->keys.start_request,0x22,32);
  memset(f->keys.start_reply,0x33,32); memset(f->keys.renew_request,0x44,32);
  memset(f->keys.renew_reply,0x55,32);
  uint8_t material[384]={0};
  memset(material,0x99,32);
  for (size_t i=0;i<10;++i) f->ids[i][0]=(uint8_t)(i+1);
  memcpy(material+64,f->ids,320);
  memcpy(f->payload,"eltor_payhash",13);
  base16_encode(f->payload+13,sizeof(f->payload)-13,(char *)material,384);
  for (char *p=f->payload+13;*p;++p) *p=TOR_TOLOWER(*p);
  if (payment_origin_configure_enabled(true)) return -1;
  f->hop->payment_export_requested=true;
  if (payment_origin_pin(f->circ,f->hop,f->payload,strlen(f->payload),1000)) return -1;
  f->hop->payment_keys=tor_memdup(&f->keys,sizeof(f->keys));
  char traffic[CPATH_KEY_MATERIAL_LEN]={0};
  if (cpath_init_circuit_crypto(RELAY_CRYPTO_ALG_TOR1,f->hop,traffic,
                                 sizeof(traffic))<0) return -1;
  f->hop->state=CPATH_STATE_OPEN;
  if (payment_origin_handshake_complete(f->circ,f->hop,1500)) return -1;
  payment_profile_terms_digest(f->q,&f->policy);
  payment_profile_initial_digest(f->a0,f->keys.binding,f->q,f->ids);
  sent_count=0;
  return 0;
}

static int
init_origin(origin_fixture_t *f)
{
  return init_origin_policy(f,false);
}

static void
clear_origin(void)
{
  circuit_free_all();
  (void)payment_origin_free_all();
  control_payment_free_all();
  timers_shutdown();
  monotime_disable_test_mocking();
  UNMOCK(relay_send_command_from_edge_);
}

static int
reply(origin_fixture_t *f, uint8_t state, uint64_t elapsed, uint64_t revision,
      uint64_t now_ms)
{
  payment_profile_message_t request,m={0};
  const uint8_t *reqkey=sent_command==PAYMENT_PROFILE_RENEW ?
    f->keys.renew_request:f->keys.start_request;
  int r=payment_profile_decode(&request,(payment_profile_command_t)sent_command,
      sent_wire,sizeof(sent_wire),reqkey,f->keys.binding);
  if (r) return r;
  uint8_t digest[32];
  payment_profile_request_digest(digest,(payment_profile_command_t)sent_command,
                                  sent_wire,sizeof(sent_wire));
  const uint8_t *repkey=f->keys.start_reply;
  if (sent_command==PAYMENT_PROFILE_COMMIT) {
    m.command=PAYMENT_PROFILE_COMMITTED;
    memcpy(m.u.committed.nonce,request.u.commit.nonce,16);
    memcpy(m.u.committed.request_digest,digest,32);
    memcpy(m.u.committed.terms,f->q,32);
    memcpy(m.u.committed.allocation,f->a0,32);
    m.u.committed.setup_remaining_ms=29000;
  } else if (sent_command==PAYMENT_PROFILE_START_STATUS) {
    m.command=PAYMENT_PROFILE_STARTED_STATUS;
    payment_profile_started_t *s=&m.u.started;
    s->state=state; memcpy(s->nonce,request.u.start.nonce,16);
    memcpy(s->request_digest,digest,32); memcpy(s->terms,f->q,32);
    memcpy(s->allocation,f->a0,32); s->revision=revision;
    if (state==3 || state==4) {
      s->elapsed_ms=elapsed; s->round=elapsed/60000+1;
      s->round_remaining_ms=(uint32_t)(60000-elapsed%60000);
      s->enforcement_remaining_ms=state==3 ? s->round_remaining_ms+15000 :
        (uint32_t)(15000-elapsed%60000);
    } else s->setup_remaining_ms=28000;
  } else {
    m.command=PAYMENT_PROFILE_RENEWED; repkey=f->keys.renew_reply;
    payment_profile_renewed_t *s=&m.u.renewed;
    s->status=state; s->period=request.u.renew.period;
    s->first_round=request.u.renew.first_round;
    memcpy(s->nonce,request.u.renew.nonce,16);
    memcpy(s->request_digest,digest,32); memcpy(s->terms,f->q,32);
    payment_profile_allocation_digest(s->allocation,f->keys.binding,
                                      sent_wire,sizeof(sent_wire));
    s->elapsed_ms=elapsed; s->activation_ms=request.u.renew.activation_ms;
    s->admit_before_ms=s->activation_ms-60000;
  }
  uint8_t wire[PAYMENT_PROFILE_WIRE_LEN];
  r=payment_profile_encode(wire,sizeof(wire),&m,repkey,f->keys.binding);
  if (r) return r;
  relay_msg_t msg={0}; msg.command=m.command; msg.length=sizeof(wire); msg.body=wire;
  return payment_origin_handle_reply(f->circ,f->hop,&msg,now_ms);
}

static void
test_origin_operations(void *arg)
{
  (void)arg;
  origin_fixture_t f;
  payment_origin_snapshot_t s;
  uint8_t op[16]={1}, nonce[16]={2};
  tt_int_op(init_origin(&f),OP_EQ,0);
  tt_int_op(payment_origin_initial_prepare(f.circ,1,op,nonce,f.policy_wire,2000),OP_EQ,0);
  tt_uint_op(sent_count,OP_EQ,1);
  tt_int_op(payment_origin_initial_prepare(f.circ,1,op,nonce,f.policy_wire,2100),OP_EQ,0);
  tt_uint_op(sent_count,OP_EQ,1);
  tt_int_op(payment_origin_get(f.circ,1,op,true,2100,&s),OP_EQ,0);
  tt_assert(!s.confirmed); tt_assert(!s.status_available);
  tt_int_op(s.phase,OP_EQ,PAYMENT_ORIGIN_SENT);
  nonce[0]=3;
  tt_int_op(payment_origin_initial_prepare(f.circ,1,op,nonce,f.policy_wire,2100),OP_EQ,
            PAYMENT_ORIGIN_CONFLICT);
  tt_int_op(reply(&f,0,0,0,2500),OP_EQ,0);
  tt_int_op(payment_origin_get(f.circ,1,op,true,2600,&s),OP_EQ,0);
  tt_assert(s.confirmed); tt_assert(s.setup_available);
  tt_assert(!s.relay_revision_available);
  tt_u64_op(s.setup_remaining_ms,OP_EQ,28400);
  op[0]=4; nonce[0]=5;
  tt_int_op(payment_origin_initial_start(f.circ,1,op,nonce,2700),OP_EQ,0);
  tt_int_op(reply(&f,2,0,3,2800),OP_EQ,0);
  tt_int_op(payment_origin_get(f.circ,1,op,true,2900,&s),OP_EQ,0);
  tt_assert(s.status_available); tt_assert(s.relay_revision_available);
  tt_assert(!s.schedule_available); tt_u64_op(s.current_round,OP_EQ,0);
  tt_int_op(reply(&f,3,0,4,3000),OP_EQ,0);
  tt_int_op(payment_origin_get(f.circ,1,op,true,3100,&s),OP_EQ,0);
  tt_assert(s.schedule_available); tt_u64_op(s.current_round,OP_EQ,1);
  tt_u64_op(s.elapsed_upper_ms,OP_EQ,400);
  tt_u64_op(s.round_remaining_ms,OP_EQ,59600);
  uint64_t revision=s.revision;
  tt_int_op(payment_origin_get(f.circ,1,NULL,true,3200,&s),OP_EQ,0);
  tt_u64_op(s.revision,OP_EQ,revision); tt_uint_op(sent_count,OP_EQ,2);
 done:
  clear_origin();
}

static uint8_t activation_fifo[4];
static unsigned activation_fifo_count;
static int
capture_activation_fifo(channel_t *chan, packed_cell_t *cell)
{
  (void)chan;
  if (activation_fifo_count < ARRAY_LENGTH(activation_fifo))
    activation_fifo[activation_fifo_count++] = cell->body[5];
  return 1;
}

static void
set_activation_time(uint64_t now_ms)
{
  monotime_set_mock_time_nsec((int64_t)now_ms*INT64_C(1000000));
  monotime_coarse_set_mock_time_nsec((int64_t)now_ms*INT64_C(1000000));
}

static void
test_origin_activation_notifications(void *arg)
{
  (void)arg;
  origin_fixture_t f;
  payment_origin_snapshot_t snapshot;
  or_connection_t conn = {0};
  channel_tls_t *chan = NULL;
  uint8_t op[16] = {1}, nonce[16] = {2};
  tt_int_op(init_origin(&f), OP_EQ, 0);
  MOCK(scheduler_channel_has_waiting_cells,
       scheduler_channel_has_waiting_cells_mock);
  MOCK(scheduler_release_channel, scheduler_release_channel_mock);
  cell_ewma_initialize_ticks();
  chan = tor_realloc(new_fake_channel(), sizeof(*chan));
  chan->base_.magic = TLS_CHAN_MAGIC;
  chan->base_.wide_circ_ids = conn.wide_circ_ids = true;
  chan->base_.write_packed_cell = capture_activation_fifo;
  chan->conn = &conn; conn.chan = chan;
  circuit_set_n_circid_chan(TO_CIRCUIT(f.circ), 40, &chan->base_);
  /* This fixture uses real queued cells and the real data-active getter. */
  f.circ->base_.state = CIRCUIT_STATE_ONIONSKIN_PENDING;
  tt_int_op(free_capacity_circuit_admit(TO_CIRCUIT(f.circ), &conn), OP_EQ, 0);
  set_activation_time(2000);
  tt_int_op(payment_origin_initial_prepare(f.circ, 1, op, nonce,
                                            f.policy_wire, 2000), OP_EQ, 0);
  tt_int_op(reply(&f, 0, 0, 0, 2100), OP_EQ, 0);
  op[0] = 3; nonce[0] = 4;
  tt_int_op(payment_origin_initial_start(f.circ, 1, op, nonce, 2200), OP_EQ, 0);
  set_activation_time(2300);
  tt_int_op(reply(&f, 3, 0, 2, 2300), OP_EQ, 0);
  tt_assert(payment_origin_data_active(f.circ, 2300));
  unsigned transmissions = sent_count;
  set_activation_time(62250);
  tt_assert(!payment_origin_data_active(f.circ, 62250));
  uint64_t revision = control_payment_revision(TO_CIRCUIT(f.circ));
  tt_int_op(payment_origin_get(f.circ, 1, op, true, 62250, &snapshot), OP_EQ,
            PAYMENT_ORIGIN_OBSERVATION_PENDING);
  tt_u64_op(control_payment_revision(TO_CIRCUIT(f.circ)), OP_EQ, revision);
  cell_t cell = { .command = CELL_RELAY, .circ_id = 40 };
  for (unsigned i = 0; i < 3; ++i) {
    cell.payload[0] = (uint8_t)(0x31+i);
    cell_queue_append_packed_copy(TO_CIRCUIT(f.circ),
        &f.circ->base_.n_chan_cells, 1, &cell, 1, 0);
  }
  packed_cell_t *first = TOR_SIMPLEQ_FIRST(&f.circ->base_.n_chan_cells.head);
  packed_cell_t *last = TOR_SIMPLEQ_NEXT(TOR_SIMPLEQ_NEXT(first, next), next);
  last->payment_control = true; /* A new QUERY behind DATA cannot jump it. */
  activation_fifo_count = 0;
  circuitmux_set_num_cells(chan->base_.cmux, TO_CIRCUIT(f.circ), 3);
  free_capacity_circuit_queued(TO_CIRCUIT(f.circ));
  tt_int_op(channel_flush_from_first_active_circuit(&chan->base_, 3), OP_EQ, 0);
  tt_uint_op(activation_fifo_count, OP_EQ, 0);
  tt_ptr_op(TOR_SIMPLEQ_FIRST(&f.circ->base_.n_chan_cells.head), OP_EQ, first);
  /* An inbound authenticated actual-round proof needs no outbound QUERY. Its
   * delayed delivery cannot buy a new full minute at receipt time. */
  set_activation_time(62700);
  tt_int_op(reply(&f, 3, 60000, 3, 62700), OP_EQ, 0);
  tt_assert(payment_origin_data_active(f.circ, 62700));
  tt_int_op(payment_origin_get(f.circ, 1, op, true, 62700, &snapshot), OP_EQ, 0);
  tt_u64_op(snapshot.current_round, OP_EQ, 2);
  tt_u64_op(snapshot.elapsed_upper_ms, OP_EQ, 60500);
  tt_u64_op(snapshot.round_remaining_ms, OP_EQ, 59500);
  tt_uint_op(sent_count, OP_EQ, transmissions);
  tt_int_op(channel_flush_from_first_active_circuit(&chan->base_, 4), OP_EQ, 3);
  tt_uint_op(activation_fifo_count, OP_EQ, 3);
  for (unsigned i = 0; i < 3; ++i)
    tt_uint_op(activation_fifo[i], OP_EQ, 0x31+i);
  tt_uint_op(payment_resources_free()->queued_bytes, OP_EQ, 0);
  revision = snapshot.revision;
  tt_int_op(reply(&f, 3, 60000, 3, 62800), OP_EQ, 0);
  tt_int_op(reply(&f, 3, 0, 2, 62900), OP_EQ, 0); /* Historical replay. */
  tt_int_op(payment_origin_get(f.circ, 1, op, true, 62900, &snapshot), OP_EQ, 0);
  tt_u64_op(snapshot.current_round, OP_EQ, 2);
  tt_u64_op(snapshot.revision, OP_EQ, revision);
  tt_u64_op(snapshot.round_remaining_ms, OP_EQ, 59300);
  /* Even a correctly MACed new-round proof delivered after its safe end
   * grants no usable capacity and does not reset the original schedule. */
  set_activation_time(183000);
  tt_int_op(reply(&f, 3, 120000, 4, 183000), OP_EQ, 0);
  tt_assert(!payment_origin_data_active(f.circ, 183000));
  tt_int_op(payment_origin_get(f.circ, 1, op, true, 183000, &snapshot), OP_EQ,
            PAYMENT_ORIGIN_OBSERVATION_PENDING);
  payment_origin_close(f.circ);
  tt_int_op(reply(&f, 3, 180000, 5, 183100), OP_EQ, 0);
  tt_assert(!payment_origin_data_active(f.circ, 183100));
 done:
  clear_origin();
  free_capacity_connection_free(&conn);
  conn.chan = NULL;
  if (chan) free_fake_channel(&chan->base_);
  (void)payment_resources_free_all();
  UNMOCK(scheduler_channel_has_waiting_cells);
  UNMOCK(scheduler_release_channel);
}

static void
test_origin_notification_invalid_clock(void *arg)
{
  (void)arg;
  origin_fixture_t f;
  payment_origin_snapshot_t snapshot;
  uint8_t op[16] = {1}, nonce[16] = {2}, start_wire[PAYMENT_PROFILE_WIRE_LEN];
  uint8_t renewal[16] = {5}, ids[10][32] = {{0}};
  tt_int_op(init_origin(&f), OP_EQ, 0);
  tt_int_op(payment_origin_initial_prepare(f.circ, 1, op, nonce,
                                            f.policy_wire, 2000), OP_EQ, 0);
  tt_int_op(reply(&f, 0, 0, 0, 2000), OP_EQ, 0);
  op[0] = 3; nonce[0] = 4;
  tt_int_op(payment_origin_initial_start(f.circ, 1, op, nonce, 2200), OP_EQ, 0);
  memcpy(start_wire, sent_wire, sizeof(start_wire));
  tt_int_op(reply(&f, 3, 0, 2, 2300), OP_EQ, 0);
  for (unsigned i = 0; i < 10; ++i) ids[i][0] = (uint8_t)(80+i);
  nonce[0] = 6;
  tt_int_op(payment_origin_renew_prepare(f.circ, 1, renewal, 1, 11, nonce,
                                       f.q, f.a0, ids, 3000), OP_EQ, 0);
  tt_int_op(reply(&f, 0, 1000, 0, 4000), OP_EQ, 0);
  /* Correct MAC and admitted allocation cannot make a future elapsed value
   * credible. Reject before moving the active allocation or granting data. */
  memcpy(sent_wire, start_wire, sizeof(start_wire));
  sent_command = PAYMENT_PROFILE_START_STATUS;
  tt_int_op(reply(&f, 3, 600000, 3, 5000), OP_EQ, 0);
  tt_assert(!payment_origin_data_active(f.circ, 5000));
  tt_int_op(payment_origin_get(f.circ, 1, op, true, 5000, &snapshot), OP_EQ, 0);
  tt_u64_op(snapshot.active_period, OP_EQ, 0);
  tt_mem_op(snapshot.active_allocation, OP_EQ, f.a0, sizeof(f.a0));
  tt_assert(!snapshot.schedule_available);
 done:
  clear_origin();
}

static void
test_origin_retries(void *arg)
{
  (void)arg;
  origin_fixture_t f;
  payment_origin_snapshot_t s;
  uint8_t op[16]={1}, nonce[16]={2}, original[463];
  tt_int_op(init_origin(&f),OP_EQ,0);
  tt_int_op(payment_origin_initial_prepare(f.circ,1,op,nonce,f.policy_wire,2000),OP_EQ,0);
  memcpy(original,sent_wire,463);
  payment_origin_tick(2999); tt_uint_op(sent_count,OP_EQ,1);
  payment_origin_tick(3000); tt_uint_op(sent_count,OP_EQ,2);
  tt_mem_op(original,OP_EQ,sent_wire,463);
  payment_origin_tick(5000); tt_uint_op(sent_count,OP_EQ,3);
  payment_origin_tick(9000); tt_uint_op(sent_count,OP_EQ,4);
  payment_origin_tick(10000); tt_uint_op(sent_count,OP_EQ,4);
  tt_int_op(payment_origin_initial_prepare(f.circ,1,op,nonce,f.policy_wire,10000),OP_EQ,0);
  tt_uint_op(sent_count,OP_EQ,4);
  payment_origin_tick(31000);
  tt_int_op(payment_origin_get(f.circ,1,op,true,31000,&s),OP_EQ,
            PAYMENT_ORIGIN_CLOSED);
  tt_ptr_op(f.hop->payment_keys,OP_EQ,NULL);
  tt_uint_op(sent_count,OP_EQ,4);
 done:
  clear_origin();
}

static void
test_origin_delayed_query_preserves_schedule(void *arg)
{
  (void)arg;
  origin_fixture_t f;
  payment_origin_snapshot_t s;
  uint8_t op[16]={1}, nonce[16]={2};
  tt_int_op(init_origin(&f),OP_EQ,0);
  tt_int_op(payment_origin_initial_prepare(f.circ,1,op,nonce,f.policy_wire,2000),OP_EQ,0);
  tt_int_op(reply(&f,0,0,0,2000),OP_EQ,0);
  op[0]=3; nonce[0]=4;
  tt_int_op(payment_origin_initial_start(f.circ,1,op,nonce,2000),OP_EQ,0);
  tt_int_op(reply(&f,3,0,5,2000),OP_EQ,0);
  op[0]=5; nonce[0]=6;
  tt_int_op(payment_origin_initial_refresh(f.circ,1,op,nonce,12000),OP_EQ,0);
  /* Six seconds outbound delay is within the seven-second query timeout. */
  tt_int_op(reply(&f,3,16000,5,18000),OP_EQ,0);
  tt_int_op(payment_origin_get(f.circ,1,NULL,true,18000,&s),OP_EQ,0);
  tt_u64_op(s.round_remaining_ms,OP_EQ,44000);
  tt_u64_op(s.elapsed_upper_ms,OP_EQ,16000);
  tt_assert(payment_origin_data_active(f.circ,61000));
  tt_assert(!payment_origin_data_active(f.circ,62000));
 done:
  clear_origin();
}

static void
test_origin_refresh_and_renew(void *arg)
{
  (void)arg;
  origin_fixture_t f;
  payment_origin_snapshot_t s;
  uint8_t op[16]={1}, nonce[16]={2};
  tt_int_op(init_origin(&f),OP_EQ,0);
  tt_int_op(payment_origin_initial_prepare(f.circ,1,op,nonce,f.policy_wire,2000),OP_EQ,0);
  tt_int_op(reply(&f,0,0,0,2000),OP_EQ,0);
  op[0]=3; nonce[0]=4;
  tt_int_op(payment_origin_initial_start(f.circ,1,op,nonce,2000),OP_EQ,0);
  tt_int_op(reply(&f,3,0,5,2000),OP_EQ,0);
  op[0]=5; nonce[0]=6;
  tt_int_op(payment_origin_initial_refresh(f.circ,1,op,nonce,3000),OP_EQ,0);
  unsigned sent=sent_count;
  payment_origin_tick(9999); tt_uint_op(sent_count,OP_EQ,sent);
  payment_origin_tick(10000);
  tt_int_op(payment_origin_get(f.circ,1,op,true,10000,&s),OP_EQ,0);
  tt_int_op(s.phase,OP_EQ,PAYMENT_ORIGIN_UNCERTAIN);
  op[0]=7; nonce[0]=8;
  tt_int_op(payment_origin_initial_refresh(f.circ,1,op,nonce,11000),OP_EQ,0);
  tt_uint_op(sent_count,OP_EQ,sent+1);
  /* A delayed observation cannot extend the original round deadline. */
  tt_int_op(reply(&f,3,1000,5,12000),OP_EQ,0);
  tt_int_op(payment_origin_get(f.circ,1,NULL,true,12000,&s),OP_EQ,0);
  tt_u64_op(s.round_remaining_ms,OP_EQ,50000);
  uint8_t ids[10][32]={0};
  for (size_t i=0;i<10;++i) ids[i][0]=(uint8_t)(i+80);
  op[0]=9; nonce[0]=10;
  tt_int_op(payment_origin_renew_prepare(f.circ,1,op,1,11,nonce,f.q,f.a0,ids,12000),OP_EQ,0);
  sent=sent_count;
  tt_int_op(payment_origin_renew_prepare(f.circ,1,op,1,11,nonce,f.q,f.a0,ids,13000),OP_EQ,0);
  tt_uint_op(sent_count,OP_EQ,sent);
  tt_int_op(reply(&f,0,10000,0,13000),OP_EQ,0);
  tt_int_op(payment_origin_get(f.circ,1,op,false,14000,&s),OP_EQ,0);
  tt_int_op(s.phase,OP_EQ,PAYMENT_ORIGIN_ADMITTED);
  tt_assert(s.allocation_available); tt_u64_op(s.period,OP_EQ,1);
 done:
  clear_origin();
}


static char *
control_query(control_connection_t *conn, const char *command, uint64_t now_ms)
{
  monotime_set_mock_time_nsec((int64_t)now_ms*INT64_C(1000000));
  monotime_coarse_set_mock_time_nsec((int64_t)now_ms*INT64_C(1000000));
  control_payment_handle_command(conn,command,strlen(command));
  char *response=smartlist_join_strings(replies,"",0,NULL);
  SMARTLIST_FOREACH(replies,char *,line,tor_free(line));
  smartlist_clear(replies);
  return response;
}

static void
lower_hex_origin(char *out, size_t capacity, const uint8_t *bytes, size_t n)
{
  base16_encode(out,capacity,(const char *)bytes,n);
  for (char *p=out;*p;++p) *p=TOR_TOLOWER(*p);
}

static void
run_control_bridge(bool final)
{
  origin_fixture_t f;
  control_connection_t conn={0};
  char *command=NULL,*response=NULL;
  uint8_t instance[16],handle[16];
  char ih[33],hh[33],policy[111];
  const char *operation="01010101010101010101010101010101";
  const char *nonce="02020202020202020202020202020202";
  tt_int_op(init_origin_policy(&f,final),OP_EQ,0);
  conn.base_.magic=CONTROL_CONNECTION_MAGIC;
  conn.base_.type=CONN_TYPE_CONTROL; conn.base_.s=TOR_INVALID_SOCKET;
  conn.base_.conn_array_index=conn.base_.closeable_list_index=-1;
  conn.base_.state=CONTROL_CONN_STATE_OPEN; conn.base_.socket_family=AF_UNSPEC;
  conn.payment_local_fd=true;
  replies=smartlist_new(); MOCK(control_write_reply,capture_control);
  tt_int_op(control_payment_binding(TO_CIRCUIT(f.circ),instance,handle),OP_EQ,0);
  lower_hex_origin(ih,sizeof(ih),instance,16);
  lower_hex_origin(hh,sizeof(hh),handle,16);
  lower_hex_origin(policy,sizeof(policy),f.policy_wire,55);
  tor_asprintf(&command,"ELTOR_INITIAL_REGISTRATION_GET 1 %s %s 1\r\n",ih,hh);
  response=control_query(&conn,command,1000);
  tt_assert(strstr(response,"250-ELTOR_INITIAL_REGISTRATION 1 "));
  tt_assert(strstr(response,policy));
  char expected_binding[65],expected_initial[65],expected_terms[65];
  lower_hex_origin(expected_binding,sizeof(expected_binding),f.keys.binding,32);
  lower_hex_origin(expected_initial,sizeof(expected_initial),f.a0,32);
  lower_hex_origin(expected_terms,sizeof(expected_terms),f.q,32);
  tt_assert(strstr(response,expected_binding));
  tt_assert(strstr(response,expected_initial));
  tt_assert(strstr(response,expected_terms));
  tt_assert(strlen(response)<2048);
  for (unsigned i=0;i<10;++i) {
    char id[65],row[90];
    lower_hex_origin(id,sizeof(id),f.ids[i],32);
    tor_snprintf(row,sizeof(row),"250-ROUND %u %s\r\n",i+1,id);
    tt_assert(strstr(response,row));
  }
  tt_uint_op(sent_count,OP_EQ,0);
  tor_free(command); tor_free(response);
  tor_asprintf(&command,"ELTOR_INITIAL_PREPARE 1 %s %s 1 %s %s %s\r\n",
                ih,hh,operation,nonce,policy);
  response=control_query(&conn,command,2000);
  tt_assert(strstr(response,"250 ELTOR_INITIAL_QUEUED 1 "));
  tor_free(response);
  response=control_query(&conn,command,2000);
  tt_assert(strstr(response,"250 ELTOR_INITIAL_QUEUED 1 "));
  tt_uint_op(sent_count,OP_EQ,1); tor_free(response); tor_free(command);
  tor_asprintf(&command,"ELTOR_INITIAL_GET 1 %s %s 1 %s\r\n",ih,hh,operation);
  response=control_query(&conn,command,3000);
  tt_assert(strstr(response,"250-PROFILE - - UNCONFIRMED -\r\n"));
  tt_assert(strstr(response,"250-CLOCK - - - - -\r\n"));
  tt_uint_op(sent_count,OP_EQ,1); tor_free(response);
  tt_int_op(reply(&f,0,0,0,3000),OP_EQ,0);
  response=control_query(&conn,command,4000);
  tt_assert(strstr(response," COMMITTED -\r\n"));
  tt_assert(strstr(response,"250-CLOCK - - - - 27000\r\n"));
  tor_free(response); tor_free(command);
  operation="03030303030303030303030303030303";
  nonce="04040404040404040404040404040404";
  tor_asprintf(&command,"ELTOR_INITIAL_START 1 %s %s 1 %s %s\r\n",ih,hh,operation,nonce);
  response=control_query(&conn,command,5000);
  tt_assert(strstr(response,"250 ELTOR_INITIAL_QUEUED 1 "));
  tor_free(response); tor_free(command);
  tt_int_op(reply(&f,2,0,5,5000),OP_EQ,0);
  tor_asprintf(&command,"ELTOR_INITIAL_GET 1 %s %s 1 %s\r\n",ih,hh,operation);
  response=control_query(&conn,command,6000);
  tt_assert(strstr(response," WAIT_PAYMENT 5\r\n"));
  tt_assert(strstr(response,"250-CLOCK 0 0 0 0 25000\r\n"));
  tor_free(response);
  tt_int_op(reply(&f,3,0,6,7000),OP_EQ,0);
  response=control_query(&conn,command,8000);
  tt_assert(strstr(response," ACTIVE 6\r\n"));
  tt_assert(strstr(response,"250-CLOCK 1 3000 57000 72000 -\r\n"));
  tor_free(response); tor_free(command);
  tor_asprintf(&command,"ELTOR_PAYMENT_GET 1 %s %s 1 -\r\n",ih,hh);
  response=control_query(&conn,command,9000);
  tt_assert(strstr(response,"250-ELTOR_PAYMENT 1 "));
  tt_assert(strstr(response,"250-OP - - - - - - -\r\n"));
  if (final) tt_assert(strstr(response,"250-SCHEDULE 56000 - 596000\r\n"));
 done:
  tor_free(command); tor_free(response);
  clear_origin(); UNMOCK(control_write_reply);
  if (replies) {
    SMARTLIST_FOREACH(replies,char *,line,tor_free(line));
    smartlist_free(replies); replies=NULL;
  }
}

static void
test_origin_control_bridge(void *arg)
{
  (void)arg;
  run_control_bridge(false);
}

static void
test_origin_control_final(void *arg)
{
  (void)arg;
  run_control_bridge(true);
}

static void
test_origin_grace_observation(void *arg)
{
  (void)arg;
  origin_fixture_t f;
  payment_origin_snapshot_t observed;
  uint8_t op[16]={1},nonce[16]={2};
  tt_int_op(init_origin(&f),OP_EQ,0);
  tt_int_op(payment_origin_initial_prepare(f.circ,1,op,nonce,f.policy_wire,2000),OP_EQ,0);
  tt_int_op(reply(&f,0,0,0,2000),OP_EQ,0);
  op[0]=3; nonce[0]=4;
  tt_int_op(payment_origin_initial_start(f.circ,1,op,nonce,2000),OP_EQ,0);
  tt_int_op(reply(&f,2,0,4,2000),OP_EQ,0);
  op[0]=5; nonce[0]=6;
  tt_int_op(payment_origin_initial_refresh(f.circ,1,op,nonce,3000),OP_EQ,0);
  tt_int_op(reply(&f,3,0,5,3000),OP_EQ,0);
  op[0]=7; nonce[0]=8;
  tt_int_op(payment_origin_initial_refresh(f.circ,1,op,nonce,63000),OP_EQ,0);
  tt_int_op(reply(&f,4,60000,6,63000),OP_EQ,0);
  tt_int_op(payment_origin_get(f.circ,1,NULL,true,63000,&observed),OP_EQ,0);
  tt_u64_op(observed.enforcement_remaining_ms,OP_EQ,15000);
  op[0]=9; nonce[0]=10;
  tt_int_op(payment_origin_initial_refresh(f.circ,1,op,nonce,64000),OP_EQ,0);
  tt_int_op(reply(&f,3,61000,7,65000),OP_EQ,0);
  tt_int_op(payment_origin_get(f.circ,1,NULL,true,65000,&observed),OP_EQ,0);
  tt_u64_op(observed.enforcement_remaining_ms,OP_EQ,73000);
  tt_u64_op(observed.round_remaining_ms,OP_EQ,58000);
  /* Authenticated lower revisions finish that operation, without rollback. */
  tt_int_op(reply(&f,4,61000,6,66000),OP_EQ,0);
  tt_int_op(payment_origin_get(f.circ,1,op,true,66000,&observed),OP_EQ,0);
  tt_uint_op(observed.state,OP_EQ,3); tt_u64_op(observed.relay_revision,OP_EQ,7);
  tt_uint_op(observed.phase,OP_EQ,PAYMENT_ORIGIN_VERIFIED);
 done:
  clear_origin();
}

static void
test_origin_authenticated_conflict(void *arg)
{
  (void)arg;
  origin_fixture_t f;
  payment_origin_snapshot_t observed;
  uint8_t op[16]={1},nonce[16]={2};
  tt_int_op(init_origin(&f),OP_EQ,0);
  tt_int_op(payment_origin_initial_prepare(f.circ,1,op,nonce,f.policy_wire,2000),OP_EQ,0);
  /* Valid MAC and request binding, but another accepted policy is a protocol
   * contradiction, not authority to replace the pinned descriptor. */
  f.q[0]^=1;
  tt_int_op(reply(&f,0,0,0,2100),OP_EQ,0);
  tt_int_op(payment_origin_get(f.circ,1,op,true,2200,&observed),OP_EQ,0);
  tt_assert(!observed.confirmed);
  tt_uint_op(observed.phase,OP_EQ,PAYMENT_ORIGIN_UNCERTAIN);
  op[0]=3; nonce[0]=4;
  tt_int_op(payment_origin_initial_prepare(f.circ,1,op,nonce,f.policy_wire,2300),OP_EQ,
            PAYMENT_ORIGIN_CONFLICT); /* one immutable COMMIT per hop */
  tt_uint_op(sent_count,OP_EQ,1);
 done:
  clear_origin();
}

static void
run_free_construction(bool acknowledged)
{
  origin_circuit_t *circ=NULL;
  or_connection_t conn={0}; channel_tls_t chan={0};
  uint8_t bytes[384]={0}; char payload[782];
  timers_initialize(); monotime_enable_test_mocking();
  monotime_set_mock_time_nsec(INT64_C(1000000000));
  monotime_coarse_set_mock_time_nsec(INT64_C(1000000000));
  extend_info_t info={0}; info.supports_ntor_v3=info.payment_free_v1=true;
  circ=origin_circuit_new(); circ->base_.purpose=CIRCUIT_PURPOSE_CONTROLLER;
  tt_int_op(cpath_append_hop(&circ->cpath,&info),OP_EQ,0);
  chan.base_.magic=TLS_CHAN_MAGIC; chan.base_.wide_circ_ids=1; chan.conn=&conn;
  circ->base_.n_chan=&chan.base_;
  for (size_t i=0;i<10;++i) bytes[64+i*32]=(uint8_t)(i+1);
  memcpy(payload,"eltor_payhash",13);
  lower_hex_origin(payload+13,sizeof(payload)-13,bytes,sizeof(bytes));
  tt_int_op(payment_origin_configure_enabled(false),OP_EQ,0);
  tt_int_op(payment_origin_prepare_handshake(circ,circ->cpath,payload,1000),OP_EQ,0);
  tt_ptr_op(circ->base_.free_capacity,OP_EQ,NULL);
  tt_assert(!circ->cpath->payment_export_requested);
  tt_int_op(payment_origin_configure_enabled(true),OP_EQ,0);
  tt_int_op(payment_origin_prepare_handshake(circ,circ->cpath,payload,1000),OP_EQ,0);
  tt_assert(circ->cpath->payment_export_requested);
  tt_assert(circ->base_.free_capacity);
  tt_ptr_op(circ->cpath->payment_profile,OP_EQ,NULL); /* no paid-start capability */
  uint64_t credit=payment_resources_free()->admissions.credit_milli;
  if (!acknowledged) {
    circ->cpath->payment_keys=tor_malloc_zero(sizeof(*circ->cpath->payment_keys));
    tt_int_op(payment_origin_resource_complete(circ,circ->cpath,false,1500),OP_EQ,-1);
    tt_assert(!circ->cpath->payment_export_requested);
    tt_ptr_op(circ->cpath->payment_keys,OP_EQ,NULL);
  } else {
    circ->cpath->payment_keys=tor_malloc_zero(sizeof(*circ->cpath->payment_keys));
    tt_int_op(payment_origin_resource_complete(circ,circ->cpath,true,1500),OP_EQ,0);
    tt_u64_op(payment_resources_free()->admissions.credit_milli,OP_EQ,credit);
    payment_origin_registration_t registration;
    tt_int_op(payment_origin_get_registration(circ,1,1500,&registration),OP_EQ,
              PAYMENT_ORIGIN_UNSUPPORTED);
    monotime_set_mock_time_nsec(INT64_C(32000000000));
    tt_int_op(free_capacity_circuit_send(TO_CIRCUIT(circ),&chan.base_),OP_EQ,
              FREE_CAPACITY_OK); /* independent free lifetime exceeds paid setup */
    tt_assert(!circ->base_.marked_for_close);
  }
 done:
  if (circ) circ->base_.n_chan=NULL;
  circuit_free_all(); (void)payment_origin_free_all(); control_payment_free_all();
  free_capacity_connection_free(&conn); (void)payment_resources_free_all();
  timers_shutdown(); monotime_disable_test_mocking();
}

static void
test_origin_free_construction(void *arg)
{ (void)arg; run_free_construction(true); }
static void
test_origin_missing_resource_ack(void *arg)
{ (void)arg; run_free_construction(false); }

static void
test_origin_no_application_fallback(void *arg)
{
  (void)arg;
  origin_circuit_t *circ=NULL;
  entry_connection_t entry={0}; socks_request_t socks={0};
  extend_info_t info={0};
  or_connection_t conn={0}; channel_tls_t chan={0};
  timers_initialize();
  circ=origin_circuit_new();
  circ->base_.purpose=CIRCUIT_PURPOSE_C_GENERAL;
  circ->base_.state=CIRCUIT_STATE_OPEN;
  circ->build_state=tor_malloc_zero(sizeof(*circ->build_state));
  info.supports_ntor_v3=info.payment_free_v1=true;
  tt_int_op(cpath_append_hop(&circ->cpath,&info),OP_EQ,0);
  tt_int_op(payment_origin_configure_enabled(true),OP_EQ,0);
  /* A missing controller, absent payload, or a legacy open circuit cannot
   * supply an alternate application path. The original stream stays pending. */
  tt_assert(!payment_origin_streams_ready(circ,1000));
  tt_int_op(payment_origin_prepare_handshake(circ,circ->cpath,NULL,1000),OP_EQ,-1);
  ENTRY_TO_CONN(&entry)->state=AP_CONN_STATE_CONTROLLER_WAIT;
  entry.socks_request=&socks;
  tt_int_op(connection_ap_handshake_attach_chosen_circuit(&entry,circ,NULL),OP_EQ,0);
  tt_uint_op(ENTRY_TO_CONN(&entry)->state,OP_EQ,AP_CONN_STATE_CONTROLLER_WAIT);
  tt_ptr_op(ENTRY_TO_EDGE_CONN(&entry)->on_circuit,OP_EQ,NULL);
  /* The one-hop directory constructor exception does not grant application
   * stream eligibility; circuituse separately checks use_begindir. */
  circ->build_state->onehop_tunnel=true;
  chan.base_.magic=TLS_CHAN_MAGIC; chan.base_.wide_circ_ids=true;
  chan.conn=&conn; circ->base_.n_chan=&chan.base_;
  tt_int_op(payment_origin_prepare_handshake(circ,circ->cpath,NULL,1000),OP_EQ,0);
  tt_assert(circ->base_.free_capacity);
  tt_int_op(payment_origin_resource_complete(circ,circ->cpath,false,1000),OP_EQ,0);
  tt_assert(free_capacity_circuit_is_bootstrap(TO_CIRCUIT(circ)));
  tt_assert(!free_capacity_circuit_is_normal(TO_CIRCUIT(circ)));
  tt_assert(!payment_origin_streams_ready(circ,1000));
  /* A path mixing signed free-only and paid-start hops is rejected before
   * any new provisional reservation or crypto allocation. Existing bootstrap
   * admission cannot become a normal authenticated profile. */
  info.payment_start_v1=true;
  tt_int_op(cpath_append_hop(&circ->cpath,&info),OP_EQ,0);
  tt_int_op(payment_origin_prepare_handshake(circ,circ->cpath,"invalid",1000),OP_EQ,-1);
  tt_assert(free_capacity_circuit_is_bootstrap(TO_CIRCUIT(circ)));
 done:
  if (circ) circ->base_.n_chan=NULL;
  circuit_free_all(); (void)payment_origin_free_all(); control_payment_free_all();
  free_capacity_connection_free(&conn);
  (void)payment_resources_free_all(); timers_shutdown();
}

#ifdef HAVE_MODULE_RELAY
static void
test_origin_reachability_descriptor(void *arg)
{
  (void)arg;
  routerinfo_t router = {0};
  extend_info_t *info = NULL;
  curve25519_public_key_t onion_key = {{1}};
  payment_profile_policy_t policy = payment_profile_testing_policy();
  router.onion_curve25519_pkey = &onion_key;
  router.nickname = (char *)"synthetic";
  router.protocol_list = (char *)"Relay=1-5";
  router.ipv4_orport = 9001;
  tt_int_op(tor_addr_parse(&router.ipv4_addr, "127.0.0.1"), OP_EQ, AF_INET);
  router.payment_start_v1 = router.payment_renew_v1 = router.payment_free_v1 = true;
  policy.rate_msat = 1500;
  tt_int_op(payment_profile_policy_encode(router.payment_profile_terms, 55,
                                          &policy), OP_EQ, 0);
  /* The synthetic marker isolates propagation; signed descriptor validation
   * itself is covered by the dir/formats_rsa_ed25519 regression. */
  router.cache_info.signed_descriptor_body = (char *)"synthetic local descriptor";
  info = selftest_extend_info_from_router(&router, AF_INET);
  tt_assert(info);
  tt_assert(info->supports_ntor_v3 && info->payment_free_v1 &&
            info->payment_start_v1 && info->payment_renew_v1);
  tt_mem_op(info->payment_profile_terms, OP_EQ, router.payment_profile_terms, 55);
  tt_assert(!info->use_congestion_control);
  extend_info_free(info); info = NULL;
  router.cache_info.signed_descriptor_body = NULL;
  info = selftest_extend_info_from_router(&router, AF_INET);
  tt_assert(info); tt_assert(!info->payment_free_v1);
  extend_info_free(info); info = NULL;
  router.cache_info.signed_descriptor_body = (char *)"synthetic local descriptor";
  router.protocol_list = (char *)"Relay=1";
  info = selftest_extend_info_from_router(&router, AF_INET);
  tt_assert(info); tt_assert(!info->payment_free_v1 && !info->supports_ntor_v3);
 done:
  extend_info_free(info);
}
#endif

static void
test_origin_reachability(void *arg)
{
  (void)arg;
  origin_circuit_t *circ = NULL;
  extend_info_t info = {0};
  or_connection_t conn = {0}; channel_tls_t chan = {0};
  protocol_budget_memory_t fill = {0};
  char payload[782], retained[3*768+1];
  uint8_t decoded[384], hash[32], ids[3][10][32];
  entry_connection_t entry = {0}; socks_request_t socks = {0};
  timers_initialize(); monotime_enable_test_mocking();
  monotime_set_mock_time_nsec(INT64_C(1000000000));
  monotime_coarse_set_mock_time_nsec(INT64_C(1000000000));
  circ = origin_circuit_new();
  circ->base_.purpose = CIRCUIT_PURPOSE_C_GENERAL;
  circ->build_state = tor_malloc_zero(sizeof(*circ->build_state));
  circ->build_state->desired_path_len = 3;
  circ->build_state->is_internal = true;
  info.supports_ntor_v3 = info.payment_free_v1 = true;
  info.payment_start_v1 = info.payment_renew_v1 = true;
  for (unsigned i = 0; i < 3; ++i)
    tt_int_op(cpath_append_hop(&circ->cpath, &info), OP_EQ, 0);
  tt_int_op(payment_origin_configure_enabled(true), OP_EQ, 0);
  tt_int_op(payment_origin_prepare_reachability(circ), OP_EQ, -1);
  circ->base_.purpose = CIRCUIT_PURPOSE_TESTING;
  circ->cpath->next->extend_info->payment_free_v1 = false;
  tt_int_op(payment_origin_prepare_reachability(circ), OP_EQ, -1);
  tt_ptr_op(circ->payhashes, OP_EQ, NULL);
  tt_assert(!circ->payment_construction_memory.active);
  circ->cpath->next->extend_info->payment_free_v1 = true;
  protocol_budget_t *owner = payment_resources_protocol();
  tt_int_op(payment_resources_reserve(&fill,
                   owner->limits.arena_bytes - owner->arena_used), OP_EQ, 0);
  tt_int_op(payment_origin_prepare_reachability(circ), OP_EQ, -1);
  tt_ptr_op(circ->payhashes, OP_EQ, NULL);
  tt_assert(!circ->payment_construction_memory.active);
  tt_int_op(payment_resources_release(&fill), OP_EQ, 0);
  tt_int_op(payment_origin_prepare_reachability(circ), OP_EQ, 0);
  tt_assert(circ->payment_internal_free);
  tt_uint_op(circ->payment_construction_hops, OP_EQ, 3);
  tt_uint_op(circ->payment_payhash_capacity, OP_EQ, sizeof(retained));
  tt_uint_op(strlen(circ->payhashes), OP_EQ, sizeof(retained)-1);
  memcpy(retained, circ->payhashes, sizeof(retained));
  uint32_t memory = owner->arena_used;
  tt_int_op(payment_origin_prepare_reachability(circ), OP_EQ, 0);
  tt_mem_op(circ->payhashes, OP_EQ, retained, sizeof(retained));
  tt_uint_op(owner->arena_used, OP_EQ, memory);
  chan.base_.magic = TLS_CHAN_MAGIC; chan.base_.wide_circ_ids = true;
  chan.conn = &conn; circ->base_.n_chan = &chan.base_;
  crypt_path_t *hop = circ->cpath;
  for (unsigned i = 0; i < 3; ++i, hop = hop->next) {
    payment_initial_material_t material;
    tt_int_op(payment_util_get_hop_payhash(circ, hop, payload, sizeof(payload)),
              OP_EQ, 1);
    tt_int_op(payment_initial_parse(&material, (const uint8_t *)payload,
                                    strlen(payload)), OP_EQ, 0);
    tt_int_op(base16_decode((char *)decoded, sizeof(decoded), payload+13, 768),
              OP_EQ, sizeof(decoded));
    tt_int_op(crypto_digest256((char *)hash, (const char *)decoded+32, 32,
                               DIGEST_SHA256), OP_EQ, 0);
    tt_mem_op(hash, OP_EQ, decoded, 32);
    memcpy(ids[i], material.ids, sizeof(ids[i]));
    for (unsigned prior = 0; prior < i; ++prior)
      for (unsigned a = 0; a < 10; ++a)
        for (unsigned b = 0; b < 10; ++b)
          tt_mem_op(ids[prior][a], OP_NE, ids[i][b], 32);
    payment_initial_clear(&material);
    tt_int_op(payment_origin_prepare_handshake(circ, hop, payload, 1000),
              OP_EQ, 0);
    tt_ptr_op(hop->payment_profile, OP_EQ, NULL); /* no financial authority */
    hop->payment_keys = tor_malloc_zero(sizeof(*hop->payment_keys));
    tt_int_op(payment_origin_resource_complete(circ, hop, true, 1000), OP_EQ, 0);
    hop->state = CPATH_STATE_OPEN;
  }
  tt_uint_op(payment_resources_free()->live_circuits, OP_EQ, 1);
  payment_origin_registration_t registration;
  tt_int_op(payment_origin_get_registration(circ, 1, 1000, &registration),
            OP_EQ, PAYMENT_ORIGIN_UNSUPPORTED);
  for (unsigned i = 0; i < 128; ++i)
    tt_int_op(free_capacity_circuit_send(TO_CIRCUIT(circ), &chan.base_),
              OP_EQ, FREE_CAPACITY_OK);
  tt_int_op(free_capacity_circuit_send(TO_CIRCUIT(circ), &chan.base_),
            OP_EQ, FREE_CAPACITY_WAIT);
  tt_assert(!payment_origin_streams_ready(circ, 1000));
  /* Even an unrelated local purpose mutation cannot turn a retained internal
   * owner into an application circuit or cannibalization candidate. */
  circ->base_.purpose = CIRCUIT_PURPOSE_C_GENERAL;
  circ->base_.state = CIRCUIT_STATE_OPEN;
  tt_ptr_op(circuit_find_to_cannibalize(CIRCUIT_PURPOSE_C_INTRODUCING, NULL,
                                      CIRCLAUNCH_IS_INTERNAL), OP_EQ, NULL);
  ENTRY_TO_CONN(&entry)->state = AP_CONN_STATE_CONTROLLER_WAIT;
  entry.socks_request = &socks;
  tt_int_op(connection_ap_handshake_attach_chosen_circuit(&entry, circ, NULL),
            OP_EQ, 0);
  tt_ptr_op(ENTRY_TO_EDGE_CONN(&entry)->on_circuit, OP_EQ, NULL);
  tt_int_op(payment_origin_prepare_handshake(circ, circ->cpath, payload, 1000),
            OP_EQ, -1);
 done:
  (void)payment_resources_release(&fill);
  if (circ) circ->base_.n_chan = NULL;
  circuit_free_all(); (void)payment_origin_free_all(); control_payment_free_all();
  free_capacity_connection_free(&conn); (void)payment_resources_free_all();
  timers_shutdown(); monotime_disable_test_mocking();
}

/* Ordinary native construction at paid-capable positive-price relays uses the
 * same canonical material, but authenticated base admission grants no money or
 * ACTIVE claim. Missing ACKs cannot expose even a partially built path. */
static void
test_origin_ordinary_base(void *arg)
{
  (void)arg;
  origin_circuit_t *circ = NULL;
  extend_info_t info = {0};
  or_connection_t conn = {0}; channel_tls_t chan = {0};
  char payload[782], retained[3*768+1];
  uint8_t ids[3][10][32];
  timers_initialize(); monotime_enable_test_mocking();
  monotime_set_mock_time_nsec(INT64_C(1000000000));
  monotime_coarse_set_mock_time_nsec(INT64_C(1000000000));
  circ = origin_circuit_new();
  circ->base_.purpose = CIRCUIT_PURPOSE_C_GENERAL;
  circ->build_state = tor_malloc_zero(sizeof(*circ->build_state));
  circ->build_state->desired_path_len = 3;
  info.supports_ntor_v3 = info.payment_free_v1 = true;
  info.payment_start_v1 = info.payment_renew_v1 = true;
  payment_profile_policy_t policy = payment_profile_testing_policy();
  policy.rate_msat = 5000; policy.initial_handshake_fee_msat = 7000;
  tt_int_op(payment_profile_policy_encode(info.payment_profile_terms,
                 sizeof(info.payment_profile_terms), &policy), OP_EQ, 0);
  for (unsigned i = 0; i < 3; ++i)
    tt_int_op(cpath_append_hop(&circ->cpath, &info), OP_EQ, 0);
  tt_int_op(payment_origin_configure_enabled(true), OP_EQ, 0);
  circ->cpath->next->extend_info->payment_free_v1 = false;
  tt_int_op(payment_origin_prepare_base(circ), OP_EQ, -1);
  tt_ptr_op(circ->payhashes, OP_EQ, NULL);
  tt_assert(!circ->payment_base_only);
  circ->cpath->next->extend_info->payment_free_v1 = true;
  tt_int_op(payment_origin_prepare_base(circ), OP_EQ, 0);
  tt_assert(circ->payment_base_only); tt_assert(!circ->payment_internal_free);
  tt_uint_op(strlen(circ->payhashes), OP_EQ, sizeof(retained)-1);
  memcpy(retained, circ->payhashes, sizeof(retained));
  tt_int_op(payment_origin_prepare_base(circ), OP_EQ, 0);
  tt_mem_op(circ->payhashes, OP_EQ, retained, sizeof(retained));
  chan.base_.magic = TLS_CHAN_MAGIC; chan.base_.wide_circ_ids = true;
  chan.conn = &conn; circ->base_.n_chan = &chan.base_;
  crypt_path_t *hop = circ->cpath;
  for (unsigned i = 0; i < 3; ++i, hop = hop->next) {
    payment_initial_material_t material = {0};
    tt_int_op(payment_util_get_hop_payhash(circ, hop, payload, sizeof(payload)),
              OP_EQ, 1);
    tt_uint_op(strlen(payload), OP_EQ, 781);
    tt_int_op(payment_initial_parse(&material, (const uint8_t *)payload,
                                    strlen(payload)), OP_EQ, 0);
    memcpy(ids[i], material.ids, sizeof(ids[i]));
    for (unsigned prior = 0; prior < i; ++prior)
      for (unsigned a = 0; a < 10; ++a)
        for (unsigned b = 0; b < 10; ++b)
          tt_mem_op(ids[prior][a], OP_NE, ids[i][b], 32);
    payment_initial_clear(&material);
    tt_int_op(payment_origin_prepare_handshake(circ, hop, payload, 1000),
              OP_EQ, 0);
    tt_assert(!payment_origin_streams_ready(circ, 1000));
    tt_int_op(payment_origin_pin(circ, hop, payload, strlen(payload), 1000),
              OP_EQ, PAYMENT_ORIGIN_UNSUPPORTED);
    tt_ptr_op(hop->payment_profile, OP_EQ, NULL);
    hop->payment_keys = tor_malloc_zero(sizeof(*hop->payment_keys));
    tt_int_op(payment_origin_resource_complete(circ, hop, true, 1000), OP_EQ, 0);
    tt_assert(!payment_origin_streams_ready(circ, 1000));
    char traffic[CPATH_KEY_MATERIAL_LEN] = {0};
    tt_int_op(cpath_init_circuit_crypto(RELAY_CRYPTO_ALG_TOR1, hop, traffic,
                                       sizeof(traffic)), OP_EQ, 0);
    hop->state = CPATH_STATE_OPEN;
  }
  tt_assert(payment_origin_streams_ready(circ, 1000));
  tt_assert(!payment_origin_data_active(circ, 1000));
  payment_origin_registration_t registration;
  tt_int_op(payment_origin_get_registration(circ, 1, 1000, &registration),
            OP_EQ, PAYMENT_ORIGIN_UNSUPPORTED);
  uint8_t op[16] = {1}, nonce[16] = {2};
  tt_int_op(payment_origin_initial_prepare(circ, 1, op, nonce,
                       info.payment_profile_terms, 1000),
            OP_EQ, PAYMENT_ORIGIN_CLOSED);
  for (unsigned i = 0; i < 128; ++i)
    tt_int_op(free_capacity_circuit_send(TO_CIRCUIT(circ), &chan.base_),
              OP_EQ, FREE_CAPACITY_OK);
  tt_int_op(free_capacity_circuit_send(TO_CIRCUIT(circ), &chan.base_),
            OP_EQ, FREE_CAPACITY_WAIT);
  tt_assert(!payment_origin_streams_ready(circ, 999)); /* no clock rollback */
  tt_assert(!payment_origin_streams_ready(circ, 601000));
  monotime_set_mock_time_nsec(INT64_C(601000000000));
  tt_int_op(free_capacity_circuit_send(TO_CIRCUIT(circ), &chan.base_),
            OP_EQ, FREE_CAPACITY_CLOSE);
 done:
  if (circ) circ->base_.n_chan = NULL;
  circuit_free_all(); (void)payment_origin_free_all(); control_payment_free_all();
  free_capacity_connection_free(&conn); (void)payment_resources_free_all();
  timers_shutdown(); monotime_disable_test_mocking();
}

static void
test_origin_setup_work_limits(void *arg)
{
  (void)arg;
  origin_circuit_t *circs[4] = {0};
  extend_info_t info = {0};
  uint8_t skin[MAX_CREATE_LEN], retained[MAX_CREATE_LEN];
  uint8_t reply[CREATED_FAST_LEN], server_keys[CPATH_KEY_MATERIAL_LEN];
  uint8_t keys[MAX_RELAY_KEY_MATERIAL_LEN], nonce[DIGEST_LEN];
  circuit_params_t params; payment_profile_export_t exported = {0};
  const char *message = NULL;
  char *material = NULL;
  timers_initialize(); monotime_enable_test_mocking();
  monotime_set_mock_time_nsec(INT64_C(1000000000));
  monotime_coarse_set_mock_time_nsec(INT64_C(1000000000));
  protocol_budget_limits_t limits;
  protocol_budget_default_limits(&limits);
  limits.crypto_rate = limits.crypto_burst = 1;
  limits.max_running = 1;
  tt_int_op(payment_resources_configure(&limits), OP_EQ, 0);
  tt_int_op(payment_origin_configure_enabled(true), OP_EQ, 0);
  info.supports_ntor_v3 = info.payment_free_v1 = true;
  for (unsigned i = 0; i < 4; ++i) {
    circs[i] = origin_circuit_new();
    circs[i]->base_.purpose = CIRCUIT_PURPOSE_C_GENERAL;
    circs[i]->build_state = tor_malloc_zero(sizeof(*circs[i]->build_state));
    circs[i]->build_state->desired_path_len = 1;
    circs[i]->build_state->onehop_tunnel = i < 2;
    tt_int_op(cpath_append_hop(&circs[i]->cpath, &info), OP_EQ, 0);
  }
  protocol_budget_t *owner = payment_resources_protocol();
  /* Even the descriptor-bootstrap exception shares attempted setup work. */
  tt_int_op(payment_origin_prepare_base(circs[0]), OP_EQ, 0);
  memset(skin, 0x5a, sizeof(skin));
  int length = payment_origin_create_onionskin(circs[0], circs[0]->cpath,
                      ONION_HANDSHAKE_TYPE_FAST, skin, sizeof(skin), NULL);
  tt_int_op(length, OP_EQ, CREATE_FAST_LEN);
  memcpy(retained, skin, sizeof(retained));
  uint64_t deadline = circs[0]->payment_construction_deadline_ms;
  tt_int_op(payment_origin_create_onionskin(circs[0], circs[0]->cpath,
              ONION_HANDSHAKE_TYPE_FAST, skin, sizeof(skin), NULL), OP_EQ, -1);
  tt_mem_op(skin, OP_EQ, retained, sizeof(skin)); /* no regenerated ciphertext */
  tt_u64_op(owner->attempts_started, OP_EQ, 1);
  tt_u64_op(circs[0]->payment_construction_deadline_ms, OP_EQ, deadline);
  memset(skin, 0x6b, sizeof(skin)); memcpy(retained, skin, sizeof(skin));
  tt_int_op(payment_origin_create_onionskin(circs[1], circs[1]->cpath,
              ONION_HANDSHAKE_TYPE_FAST, skin, sizeof(skin), NULL), OP_EQ, PAYMENT_ORIGIN_WORK_REFUSED);
  tt_mem_op(skin, OP_EQ, retained, sizeof(skin));
  tt_uint_op(circs[1]->cpath->handshake_state.tag, OP_EQ, 0);
  tt_uint_op(owner->running, OP_EQ, 0); tt_uint_op(owner->waiting, OP_EQ, 0);
  tt_uint_op(owner->slots, OP_EQ, 0);
  monotime_set_mock_time_nsec(INT64_C(2000000000));
  tt_int_op(payment_origin_create_onionskin(circs[1], circs[1]->cpath,
              ONION_HANDSHAKE_TYPE_FAST, skin, sizeof(skin), NULL),
            OP_EQ, CREATE_FAST_LEN);
  tt_int_op(fast_server_handshake(skin, reply, server_keys,
                                  sizeof(server_keys)), OP_EQ, 0);
  /* Dummy generation has no independent lane or fresh attempt bucket. */
  tt_int_op(payment_origin_prepare_base(circs[2]), OP_EQ, -1);
  tt_assert(!circs[2]->payment_base_only);
  tt_assert(!circs[2]->cpath->payment_export_requested);
  tt_u64_op(owner->attempts_started, OP_EQ, 2);
  monotime_set_mock_time_nsec(INT64_C(3000000000));
  tt_int_op(payment_origin_prepare_base(circs[3]), OP_EQ, 0);
  tt_assert(circs[3]->payment_base_only);
  material = tor_strdup(circs[3]->payhashes);
  tt_int_op(payment_origin_prepare_base(circs[3]), OP_EQ, 0);
  tt_str_op(material, OP_EQ, circs[3]->payhashes);
  tor_free(material);
  tt_u64_op(owner->attempts_started, OP_EQ, 3);
  size_t keylen = sizeof(keys);
  memset(keys, 0x5a, sizeof(keys));
  tt_int_op(payment_origin_finish_onionskin(circs[1], circs[1]->cpath,
                reply, sizeof(reply), keys, &keylen, nonce, &params,
                &message, &exported), OP_EQ, PAYMENT_ORIGIN_WORK_REFUSED);
  tt_uint_op(keylen, OP_EQ, 0);
  tt_assert(safe_mem_is_zero(keys, sizeof(keys)));
  /* Delayed CREATED verification cannot obtain a separate crypto bucket. */
  monotime_set_mock_time_nsec(INT64_C(4000000000)); keylen = sizeof(keys);
  tt_int_op(payment_origin_finish_onionskin(circs[1], circs[1]->cpath,
                reply, sizeof(reply), keys, &keylen, nonce, &params,
                &message, &exported), OP_EQ, 0);
  tt_uint_op(keylen, OP_EQ, sizeof(server_keys));
  tt_mem_op(keys, OP_EQ, server_keys, sizeof(server_keys));
  tt_u64_op(owner->attempts_started, OP_EQ, 4);
  tt_uint_op(owner->running, OP_EQ, 0); tt_uint_op(owner->waiting, OP_EQ, 0);
  tt_uint_op(owner->slots, OP_EQ, 0);
 done:
  tor_free(material);
  circuit_free_all(); (void)payment_origin_free_all(); control_payment_free_all();
  (void)payment_workqueue_free_all(); (void)payment_resources_free_all();
  timers_shutdown(); monotime_disable_test_mocking();
}

static void
test_origin_paid_first(void *arg)
{
  (void)arg;
  origin_fixture_t paid;
  origin_circuit_t *base = NULL;
  entry_connection_t entry = {0};
  uint8_t op[16] = {1}, nonce[16] = {2};
  tt_int_op(init_origin(&paid), OP_EQ, 0);
  base = origin_circuit_new();
  base->base_.purpose = CIRCUIT_PURPOSE_C_GENERAL;
  base->build_state = tor_malloc_zero(sizeof(*base->build_state));
  base->payment_base_only = true;
  ENTRY_TO_CONN(&entry)->purpose = CIRCUIT_PURPOSE_C_GENERAL;
  tt_int_op(payment_origin_initial_prepare(paid.circ, 1, op, nonce,
                                          paid.policy_wire, 2000), OP_EQ, 0);
  tt_int_op(reply(&paid, 0, 0, 0, 2500), OP_EQ, 0);
  op[0] = 3; nonce[0] = 4;
  tt_int_op(payment_origin_initial_start(paid.circ, 1, op, nonce, 2700), OP_EQ, 0);
  tt_int_op(reply(&paid, 3, 0, 4, 3000), OP_EQ, 0);
  monotime_set_mock_time_nsec(INT64_C(3000000000));
  tt_assert(payment_origin_data_active(paid.circ, 3000));
  /* Ranking runs only after both candidates' existing eligibility checks.
   * Even a relaxed paid path wins over a newer bounded base path. */
  paid.circ->relaxed_timeout = true;
  tt_int_op(circuit_is_better(paid.circ, base, &entry), OP_EQ, 1);
  tt_int_op(circuit_is_better(base, paid.circ, &entry), OP_EQ, 0);
  tt_assert(!payment_origin_data_active(base, 3000));
 done:
  clear_origin();
}

static void
test_origin_renew_active_requires_status(void *arg)
{
  (void)arg;
  origin_fixture_t f;
  payment_origin_snapshot_t snapshot;
  control_connection_t conn={0};
  uint8_t op[16]={1},nonce[16]={2},renewal[16]={5},ids[10][32]={0};
  char *command=NULL,*response=NULL;
  uint8_t original_renewal[PAYMENT_PROFILE_WIRE_LEN];
  tt_int_op(init_origin(&f),OP_EQ,0);
  tt_int_op(payment_origin_initial_prepare(f.circ,1,op,nonce,f.policy_wire,2000),OP_EQ,0);
  tt_int_op(reply(&f,0,0,0,2000),OP_EQ,0);
  op[0]=3; nonce[0]=4;
  tt_int_op(payment_origin_initial_start(f.circ,1,op,nonce,2000),OP_EQ,0);
  tt_int_op(reply(&f,3,0,5,2000),OP_EQ,0);
  for (size_t i=0;i<10;++i) ids[i][0]=(uint8_t)(i+80);
  nonce[0]=6;
  tt_int_op(payment_origin_renew_prepare(f.circ,1,renewal,1,11,nonce,f.q,f.a0,ids,3000),OP_EQ,0);
  memcpy(original_renewal,sent_wire,sizeof(original_renewal));
  tt_int_op(reply(&f,1,600000,0,4000),OP_EQ,0);
  unsigned transmissions=sent_count;
  uint64_t revision=control_payment_revision(TO_CIRCUIT(f.circ));
  tt_int_op(payment_origin_get(f.circ,1,renewal,false,4100,&snapshot),OP_EQ,
            PAYMENT_ORIGIN_OBSERVATION_PENDING);
  tt_int_op(payment_origin_get(f.circ,1,NULL,true,4200,&snapshot),OP_EQ,
            PAYMENT_ORIGIN_OBSERVATION_PENDING);
  tt_assert(!payment_origin_data_active(f.circ,4200));
  tt_u64_op(control_payment_revision(TO_CIRCUIT(f.circ)),OP_EQ,revision);
  tt_uint_op(sent_count,OP_EQ,transmissions);
  conn.base_.magic=CONTROL_CONNECTION_MAGIC; conn.base_.type=CONN_TYPE_CONTROL;
  conn.base_.s=TOR_INVALID_SOCKET; conn.base_.socket_family=AF_UNSPEC;
  conn.base_.conn_array_index=conn.base_.closeable_list_index=-1;
  conn.base_.state=CONTROL_CONN_STATE_OPEN; conn.payment_local_fd=true;
  replies=smartlist_new(); MOCK(control_write_reply,capture_control);
  uint8_t instance[16],handle[16]; char ih[33],hh[33],operation_hex[33];
  tt_int_op(control_payment_binding(TO_CIRCUIT(f.circ),instance,handle),OP_EQ,0);
  lower_hex_origin(ih,sizeof(ih),instance,16); lower_hex_origin(hh,sizeof(hh),handle,16);
  lower_hex_origin(operation_hex,sizeof(operation_hex),renewal,16);
  tor_asprintf(&command,"ELTOR_PAYMENT_GET 1 %s %s 1 %s\r\n",ih,hh,operation_hex);
  response=control_query(&conn,command,5000);
  tt_assert(strstr(response,"551 STATE_TRANSITION_PENDING\r\n"));
  tt_uint_op(sent_count,OP_EQ,transmissions); tor_free(response);
  /* Only an explicit bounded QUERY obtains the missing authenticated clocks.
   * GET neither sends nor manufactures a new round or activation. */
  op[0]=7; nonce[0]=8;
  tt_int_op(payment_origin_initial_refresh(f.circ,1,op,nonce,6000),OP_EQ,0);
  tt_uint_op(sent_count,OP_EQ,transmissions+1);
  tt_int_op(reply(&f,3,600000,6,6100),OP_EQ,0);
  tt_int_op(payment_origin_get(f.circ,1,renewal,false,6200,&snapshot),OP_EQ,0);
  tt_u64_op(snapshot.active_period,OP_EQ,1); tt_u64_op(snapshot.current_round,OP_EQ,11);
  tt_int_op(snapshot.phase,OP_EQ,PAYMENT_ORIGIN_ACTIVE);
  tt_u64_op(snapshot.round_remaining_ms,OP_EQ,59900);
  tt_u64_op(snapshot.hard_age_remaining_ms,OP_EQ,1199900);
  uint64_t hard=snapshot.hard_age_remaining_ms;
  response=control_query(&conn,command,7000);
  tt_assert(strstr(response,"250-ELTOR_PAYMENT 1 "));
  tt_assert(strstr(response," 11\r\n"));
  tt_int_op(payment_origin_get(f.circ,1,renewal,false,7100,&snapshot),OP_EQ,0);
  tt_assert(snapshot.hard_age_remaining_ms<hard);
  tt_uint_op(sent_count,OP_EQ,transmissions+1);
  /* Move coherently to the following allocation, then replay an old exact
   * ACTIVE acknowledgement. It cannot roll the live profile back or stop the
   * already valid current allocation merely because delivery was reordered. */
  uint8_t parent[32]; memcpy(parent,snapshot.active_allocation,32);
  for (size_t i=0;i<10;++i) ids[i][0]=(uint8_t)(i+110);
  op[0]=9; nonce[0]=10;
  tt_int_op(payment_origin_renew_prepare(f.circ,1,op,2,21,nonce,f.q,parent,ids,7500),OP_EQ,0);
  tt_int_op(reply(&f,1,1200000,0,8000),OP_EQ,0);
  op[0]=11; nonce[0]=12;
  tt_int_op(payment_origin_initial_refresh(f.circ,1,op,nonce,9000),OP_EQ,0);
  tt_int_op(reply(&f,3,1200000,7,9100),OP_EQ,0);
  memcpy(sent_wire,original_renewal,sizeof(original_renewal));
  sent_command=PAYMENT_PROFILE_RENEW;
  tt_int_op(reply(&f,1,600000,0,9500),OP_EQ,0);
  tt_int_op(payment_origin_get(f.circ,1,renewal,false,9600,&snapshot),OP_EQ,0);
  tt_u64_op(snapshot.active_period,OP_EQ,2); tt_u64_op(snapshot.current_round,OP_EQ,21);
  tt_assert(payment_origin_data_active(f.circ,9600));
 done:
  tor_free(command); tor_free(response);
  clear_origin(); UNMOCK(control_write_reply);
  if (replies) {SMARTLIST_FOREACH(replies,char *,line,tor_free(line));smartlist_free(replies);replies=NULL;}
}

struct testcase_t payment_origin_tests[]={
  {"operations",test_origin_operations,TT_FORK,NULL,NULL},
  {"activation_notifications",test_origin_activation_notifications,TT_FORK,NULL,NULL},
  {"notification_invalid_clock",test_origin_notification_invalid_clock,TT_FORK,NULL,NULL},
  {"retries",test_origin_retries,TT_FORK,&helper_pubsub_setup,NULL},
  {"delayed_query_preserves_schedule",test_origin_delayed_query_preserves_schedule,TT_FORK,NULL,NULL},
  {"refresh_and_renew",test_origin_refresh_and_renew,TT_FORK,NULL,NULL},
  {"renew_active_requires_status",test_origin_renew_active_requires_status,TT_FORK,NULL,NULL},
  {"control_bridge",test_origin_control_bridge,TT_FORK,NULL,NULL},
  {"control_final",test_origin_control_final,TT_FORK,NULL,NULL},
  {"grace_observation",test_origin_grace_observation,TT_FORK,NULL,NULL},
  {"authenticated_conflict",test_origin_authenticated_conflict,TT_FORK,NULL,NULL},
  {"no_application_fallback",test_origin_no_application_fallback,TT_FORK,NULL,NULL},
  {"free_construction",test_origin_free_construction,TT_FORK,NULL,NULL},
  {"reachability",test_origin_reachability,TT_FORK,NULL,NULL},
  {"ordinary_base",test_origin_ordinary_base,TT_FORK,NULL,NULL},
  {"setup_work_limits",test_origin_setup_work_limits,TT_FORK,NULL,NULL},
  {"paid_first",test_origin_paid_first,TT_FORK,NULL,NULL},
#ifdef HAVE_MODULE_RELAY
  {"reachability_descriptor",test_origin_reachability_descriptor,TT_FORK,NULL,NULL},
#endif
  {"missing_resource_ack",test_origin_missing_resource_ack,TT_FORK,NULL,NULL},
  END_OF_TESTCASES
};
