/* See LICENSE for licensing information. */
#define CHANNEL_OBJECT_PRIVATE
#include "orconfig.h"
#include "core/or/or.h"
#include "core/or/or_circuit_st.h"
#include "core/or/or_connection_st.h"
#include "core/or/channeltls.h"
#include "core/or/circuitlist.h"
#include "core/or/relay.h"
#include "core/or/relay_msg_st.h"
#include "feature/payment/payment_circuit.h"
#include "feature/payment/free_capacity_hooks.h"
#include "feature/payment/payment_resources.h"
#include "lib/time/compat_time.h"
#include "feature/control/control_payment.h"
#include "lib/evloop/timers.h"
#include "test/test.h"

static uint8_t reply_wire[PAYMENT_PROFILE_WIRE_LEN];
static unsigned reply_command, reply_count;

static int
capture_reply(streamid_t stream, circuit_t *circ, uint8_t command,
              const char *payload, size_t len, crypt_path_t *layer,
              const char *file, int line)
{
  (void)circ; (void)layer; (void)file; (void)line;
  if (stream || len != sizeof(reply_wire)) return -1;
  memcpy(reply_wire, payload, len);
  reply_command = command;
  ++reply_count;
  return 0;
}

typedef struct test_fixture_t {
  or_circuit_t *circ;
  payment_profile_policy_t policy;
  payment_profile_keys_t keys;
  uint8_t ids[10][32], fee_hash[32], q[32], a0[32];
} test_fixture_t;

static int
fixture_init_prices(test_fixture_t *f, bool zero)
{
  memset(f, 0, sizeof(*f));
  reply_count = reply_command = 0;
  timers_initialize();
  MOCK(relay_send_command_from_edge_, capture_reply);
  f->policy.rate_msat = zero ? 0 : 1000;
  f->policy.initial_handshake_fee_msat = zero ? 0 : 10;
  f->policy.grace_ms = 15000;
  f->policy.max_age_ms = 1800000;
  f->policy.max_periods = 3;
  f->policy.setup_timeout_ms = 30000;
  memset(f->keys.binding, 2, 32);
  memset(f->keys.renew_request, 3, 32);
  memset(f->keys.renew_reply, 4, 32);
  memset(f->keys.start_request, 5, 32);
  memset(f->keys.start_reply, 6, 32);
  for (size_t i = 0; i < 10; ++i) f->ids[i][0] = (uint8_t)(i+1);
  memset(f->fee_hash, 0x99, 32);
  f->circ = or_circuit_new(0, NULL);
  f->circ->base_.purpose = CIRCUIT_PURPOSE_OR;
  f->circ->payment_export_requested = true;
  f->circ->payment_keys = tor_memdup(&f->keys, sizeof(f->keys));
  payment_profile_terms_digest(f->q, &f->policy);
  payment_profile_initial_digest(f->a0, f->keys.binding, f->q, f->ids);
  return payment_circuit_attach(f->circ, &f->policy, f->ids, f->fee_hash,
                                 1000, 1000);
}

static int
fixture_init(test_fixture_t *f)
{
  return fixture_init_prices(f, false);
}

static void
fixture_clear(void)
{
  circuit_free_all();
  control_payment_free_all();
  timers_shutdown();
  UNMOCK(relay_send_command_from_edge_);
}

static int
send_request(test_fixture_t *f, const payment_profile_message_t *m,
              uint64_t now_ms)
{
  uint8_t wire[PAYMENT_PROFILE_WIRE_LEN];
  const uint8_t *key = m->command == PAYMENT_PROFILE_RENEW ?
                      f->keys.renew_request : f->keys.start_request;
  int r = payment_profile_encode(wire, sizeof(wire), m, key, f->keys.binding);
  if (r) return r;
  relay_msg_t msg = {0};
  msg.command = m->command; msg.length = sizeof(wire); msg.body = wire;
  return payment_circuit_handle_relay(f->circ, &msg, now_ms);
}

static int
read_reply(test_fixture_t *f, payment_profile_message_t *m)
{
  const uint8_t *key = reply_command == PAYMENT_PROFILE_RENEWED ?
                      f->keys.renew_reply : f->keys.start_reply;
  return payment_profile_decode(m, (payment_profile_command_t)reply_command,
                   reply_wire, sizeof(reply_wire), key, f->keys.binding);
}

static payment_profile_message_t
commit_request(const test_fixture_t *f)
{
  payment_profile_message_t m = { .command = PAYMENT_PROFILE_COMMIT };
  m.u.commit.policy = f->policy;
  memset(m.u.commit.nonce, 0x11, 16);
  memcpy(m.u.commit.allocation, f->a0, 32);
  return m;
}

static payment_profile_message_t
start_request(const test_fixture_t *f)
{
  payment_profile_message_t m = { .command = PAYMENT_PROFILE_START_STATUS };
  memset(m.u.start.nonce, 0x22, 16);
  memcpy(m.u.start.terms, f->q, 32);
  memcpy(m.u.start.allocation, f->a0, 32);
  m.u.start.round = 1;
  return m;
}

static int
commit_and_reserve(test_fixture_t *f, uint64_t now_ms)
{
  payment_profile_message_t m = commit_request(f);
  payment_circuit_snapshot_t snapshot;
  uint8_t decision[16] = {1};
  int r = send_request(f, &m, now_ms);
  if (r) return r;
  r = payment_circuit_get_admission(f->circ, 0, now_ms, &snapshot);
  if (r) return r;
  return payment_circuit_decide(f->circ, 0, snapshot.request_digest,
                decision, PAYMENT_CIRCUIT_RESERVED, now_ms);
}

static void
charge(const test_fixture_t *f, uint64_t round, payment_circuit_charge_t *c)
{
  memset(c, 0, sizeof(*c));
  c->decision[0] = (uint8_t)(round+5);
  c->amount_msat = round ? f->policy.rate_msat :
                         f->policy.initial_handshake_fee_msat;
  c->record_digest[0] = (uint8_t)(round+25);
  if (c->amount_msat) {
    if (!round) memcpy(c->payment_hash, f->fee_hash, 32);
    else c->payment_hash[0] = (uint8_t)(round+45);
  }
}

static int
activate(test_fixture_t *f, uint64_t now_ms)
{
  int r = commit_and_reserve(f, now_ms);
  if (r) return r;
  payment_profile_message_t start = start_request(f);
  r = send_request(f, &start, now_ms);
  if (r) return r;
  payment_circuit_charge_t fee, first;
  charge(f, 0, &fee);
  charge(f, 1, &first);
  r = payment_circuit_authorize(f->circ, 0, &fee, now_ms);
  if (r) return r;
  return payment_circuit_authorize(f->circ, 1, &first, now_ms);
}

static void
test_payment_circuit_commit_activation(void *arg)
{
  (void)arg;
  test_fixture_t f;
  payment_circuit_snapshot_t snapshot, again;
  payment_profile_message_t m, reply;
  tt_int_op(fixture_init(&f), OP_EQ, PAYMENT_CIRCUIT_OK);
  m = commit_request(&f);
  tt_int_op(send_request(&f, &m, 2000), OP_EQ, 0);
  tt_uint_op(reply_count, OP_EQ, 0); /* local receipt is not admission */
  tt_int_op(payment_circuit_get_admission(f.circ, 0, 2000, &snapshot), OP_EQ, 0);
  tt_assert(snapshot.pending);
  tt_mem_op(snapshot.circuit_binding, OP_EQ, f.keys.binding, 32);
  tt_u64_op(snapshot.admission_remaining_ms, OP_EQ, 29000);
  tt_u64_op(snapshot.constructed_elapsed_ms,OP_EQ,1000);
  tt_assert(!snapshot.commit_clock_available);
  tt_assert(!snapshot.rounds[0].window_available);
  uint64_t revision = payment_circuit_revision(f.circ);
  tt_int_op(payment_circuit_get_admission(f.circ, 0, 2500, &again), OP_EQ, 0);
  tt_u64_op(payment_circuit_revision(f.circ), OP_EQ, revision);
  tt_uint_op(reply_count, OP_EQ, 0);
  tt_int_op(payment_circuit_get_registration(f.circ, 0, 2500, &again), OP_EQ,
            PAYMENT_CIRCUIT_UNCONFIRMED);
  uint8_t decision[16] = {1}, other[16] = {2};
  tt_int_op(payment_circuit_decide(f.circ, 0, snapshot.request_digest, decision,
                   PAYMENT_CIRCUIT_RESERVED, 3000), OP_EQ, 0);
  tt_int_op(read_reply(&f, &reply), OP_EQ, 0);
  tt_int_op(reply.u.committed.status, OP_EQ, 0);
  tt_int_op(reply.u.committed.setup_remaining_ms, OP_EQ, 28000);
  tt_assert(!payment_circuit_paid_active(f.circ));
  tt_int_op(payment_circuit_get_registration(f.circ, 0, 4000, &snapshot),
            OP_EQ, 0);
  tt_u64_op(snapshot.rounds[0].closes_in_ms, OP_EQ, 27000);
  tt_assert(snapshot.commit_clock_available);
  tt_u64_op(snapshot.constructed_elapsed_ms,OP_EQ,3000);
  tt_u64_op(snapshot.commit_elapsed_ms,OP_EQ,1000);
  tt_assert(!snapshot.rounds[1].window_available);
  unsigned sent = reply_count;
  revision = payment_circuit_revision(f.circ);
  tt_int_op(payment_circuit_decide(f.circ, 0, snapshot.request_digest, decision,
                   PAYMENT_CIRCUIT_RESERVED, 4000), OP_EQ, 0);
  tt_uint_op(reply_count, OP_EQ, sent);
  tt_u64_op(payment_circuit_revision(f.circ), OP_EQ, revision);
  tt_int_op(payment_circuit_decide(f.circ, 0, snapshot.request_digest, other,
                   PAYMENT_CIRCUIT_RESERVED, 4000), OP_EQ,
            PAYMENT_CIRCUIT_CONFLICT);
  m = start_request(&f);
  tt_int_op(send_request(&f, &m, 4000), OP_EQ, 0);
  tt_int_op(read_reply(&f, &reply), OP_EQ, 0);
  tt_int_op(reply.u.started.state, OP_EQ, 2);
  payment_circuit_charge_t fee, first;
  charge(&f, 0, &fee);
  charge(&f, 1, &first);
  tt_int_op(payment_circuit_authorize(f.circ, 0, &fee, 5000), OP_EQ, 0);
  tt_assert(!payment_circuit_paid_active(f.circ));
  tt_int_op(payment_circuit_authorize(f.circ, 1, &first, 6000), OP_EQ, 0);
  tt_assert(payment_circuit_paid_active(f.circ));
  tt_int_op(payment_circuit_get_registration(f.circ, 0, 6500, &snapshot),
            OP_EQ, 0);
  tt_u64_op(snapshot.elapsed_ms, OP_EQ, 500);
  tt_int_op(snapshot.fee.authorization, OP_EQ, PAYMENT_CIRCUIT_CONSUMED);
  tt_int_op(snapshot.rounds[0].charge.authorization, OP_EQ,
            PAYMENT_CIRCUIT_CONSUMED);
  tt_assert(snapshot.rounds[1].window_available);
  revision = payment_circuit_revision(f.circ);
  tt_int_op(payment_circuit_authorize(f.circ, 1, &first, 7000), OP_EQ, 0);
  tt_u64_op(payment_circuit_revision(f.circ), OP_EQ, revision);
  /* Immutable START and allocation cannot be replaced by fresh nonces. */
  m.u.start.nonce[0] ^= 1;
  tt_int_op(send_request(&f, &m, 7000), OP_EQ, 0);
  tt_int_op(read_reply(&f, &reply), OP_EQ, 0);
  tt_int_op(reply.u.started.state, OP_EQ, 7);
  tt_int_op(payment_circuit_get_registration(f.circ, 0, 7000, &snapshot),
            OP_EQ, 0);
  tt_u64_op(snapshot.elapsed_ms, OP_EQ, 1000);
 done:
  fixture_clear();
}

static void
test_payment_circuit_refusal_and_expiry(void *arg)
{
  (void)arg;
  test_fixture_t f;
  payment_profile_message_t m, reply;
  payment_circuit_snapshot_t snapshot;
  tt_int_op(fixture_init(&f), OP_EQ, 0);
  m = commit_request(&f); ++m.u.commit.policy.rate_msat;
  tt_int_op(send_request(&f, &m, 2000), OP_EQ, 0);
  tt_int_op(read_reply(&f, &reply), OP_EQ, 0);
  tt_int_op(reply.u.committed.status, OP_EQ, 1);
  m = commit_request(&f); m.u.commit.allocation[0] ^= 1;
  tt_int_op(send_request(&f, &m, 2000), OP_EQ, 0);
  tt_int_op(read_reply(&f, &reply), OP_EQ, 0);
  tt_int_op(reply.u.committed.status, OP_EQ, 2);
  m = commit_request(&f);
  tt_int_op(send_request(&f, &m, 2000), OP_EQ, 0);
  tt_int_op(payment_circuit_get_admission(f.circ, 0, 2000, &snapshot), OP_EQ, 0);
  uint8_t decision[16] = {1};
  tt_int_op(payment_circuit_decide(f.circ, 0, snapshot.request_digest, decision,
               PAYMENT_CIRCUIT_ID_CONFLICT, 3000), OP_EQ, 0);
  tt_int_op(read_reply(&f, &reply), OP_EQ, 0);
  tt_int_op(reply.u.committed.status, OP_EQ, 2);
  unsigned sent = reply_count;
  /* Exact decision recovery past the original deadline performs no mutation. */
  tt_int_op(payment_circuit_decide(f.circ, 0, snapshot.request_digest, decision,
               PAYMENT_CIRCUIT_ID_CONFLICT, 32000), OP_EQ, 0);
  tt_uint_op(reply_count, OP_EQ, sent);
  payment_circuit_tick(f.circ, 32000);
  tt_assert(f.circ->base_.marked_for_close);
  tt_assert(!payment_circuit_present(f.circ));
  tt_ptr_op(f.circ->payment_keys, OP_EQ, NULL);
 done:
  fixture_clear();
}

static void
test_payment_circuit_round_boundaries(void *arg)
{
  (void)arg;
  test_fixture_t f;
  payment_circuit_snapshot_t snapshot;
  tt_int_op(fixture_init(&f), OP_EQ, 0);
  tt_int_op(activate(&f, 2000), OP_EQ, 0);
  payment_circuit_charge_t second, third;
  charge(&f, 2, &second);
  charge(&f, 3, &third);
  tt_int_op(payment_circuit_authorize(f.circ, 3, &third, 2000), OP_EQ,
            PAYMENT_CIRCUIT_EXPIRED);
  uint64_t revision = payment_circuit_revision(f.circ);
  payment_profile_message_t query = start_request(&f);
  query.u.start.action = 1; query.u.start.round = 0;
  unsigned sent = reply_count;
  tt_int_op(send_request(&f, &query, 62000), OP_EQ, 0);
  tt_uint_op(reply_count, OP_EQ, sent); /* timer-due QUERY is inert */
  tt_int_op(payment_circuit_get_registration(f.circ, 0, 62000, &snapshot),
            OP_EQ, PAYMENT_CIRCUIT_OBSERVATION_PENDING);
  tt_u64_op(payment_circuit_revision(f.circ), OP_EQ, revision);
  tt_assert(payment_circuit_paid_active(f.circ)); /* query did not tick */
  payment_circuit_tick(f.circ, 62000);
  tt_assert(!payment_circuit_paid_active(f.circ));
  tt_int_op(payment_circuit_get_registration(f.circ, 0, 63000, &snapshot),
            OP_EQ, 0);
  tt_int_op(snapshot.phase, OP_EQ, PAYMENT_SCHEDULE_GRACE);
  tt_u64_op(snapshot.current_round, OP_EQ, 2);
  tt_u64_op(snapshot.enforcement_remaining_ms, OP_EQ, 14000);
  tt_int_op(payment_circuit_authorize(f.circ, 2, &second, 65000), OP_EQ, 0);
  tt_assert(payment_circuit_paid_active(f.circ));
  tt_int_op(payment_circuit_get_registration(f.circ, 0, 66000, &snapshot),
            OP_EQ, 0);
  tt_u64_op(snapshot.elapsed_ms, OP_EQ, 64000); /* T0 never moves */
  tt_u64_op(snapshot.rounds[1].closes_in_ms, OP_EQ, 11000);
  third.decision[0] = second.decision[0];
  tt_int_op(payment_circuit_authorize(f.circ, 3, &third, 66000), OP_EQ,
            PAYMENT_CIRCUIT_CONFLICT);
  payment_circuit_tick(f.circ, 137000); /* round three grace elapsed */
  tt_assert(f.circ->base_.marked_for_close);
  tt_assert(!payment_circuit_paid_active(f.circ));
 done:
  fixture_clear();
}

static void
run_renewal(bool late)
{
  test_fixture_t f;
  payment_circuit_snapshot_t snapshot;
  payment_profile_message_t m, reply;
  tt_int_op(fixture_init(&f), OP_EQ, 0);
  tt_int_op(activate(&f, 2000), OP_EQ, 0);
  /* Fund each round within its original lead window, without skipping one. */
  for (unsigned round = 2; round <= 7; ++round) {
    payment_circuit_charge_t c;
    charge(&f, round, &c);
    tt_int_op(payment_circuit_authorize(f.circ, round, &c,
                       2000+(round-2)*60000), OP_EQ, 0);
  }
  payment_circuit_tick(f.circ, 362000); /* start of round seven */
  memset(&m, 0, sizeof(m)); m.command = PAYMENT_PROFILE_RENEW;
  m.u.renew.period = 1; m.u.renew.first_round = 11;
  m.u.renew.activation_ms = 600000;
  memset(m.u.renew.nonce, 0x33, 16);
  memcpy(m.u.renew.terms, f.q, 32); memcpy(m.u.renew.parent, f.a0, 32);
  for (size_t i = 0; i < 10; ++i) m.u.renew.ids[i][0] = (uint8_t)(i+80);
  unsigned sent = reply_count;
  tt_int_op(send_request(&f, &m, 362000), OP_EQ, 0);
  tt_uint_op(reply_count, OP_EQ, sent);
  tt_int_op(payment_circuit_get_admission(f.circ, 1, 362000, &snapshot),
            OP_EQ, 0);
  tt_u64_op(snapshot.first_round, OP_EQ, 11);
  tt_u64_op(snapshot.admission_remaining_ms, OP_EQ, 180000);
  uint8_t decision[16] = {2};
  tt_int_op(payment_circuit_decide(f.circ, 1, snapshot.request_digest, decision,
               PAYMENT_CIRCUIT_RESERVED, 363000), OP_EQ, 0);
  tt_int_op(read_reply(&f, &reply), OP_EQ, 0);
  tt_int_op(reply.u.renewed.status, OP_EQ, 0);
  tt_mem_op(reply.u.renewed.allocation, OP_EQ, snapshot.allocation, 32);
  payment_circuit_charge_t eleventh;
    charge(&f, 11, &eleventh);
  tt_int_op(payment_circuit_authorize(f.circ, 11, &eleventh, 363000), OP_EQ,
            PAYMENT_CIRCUIT_EXPIRED); /* admission is not early payment */
  for (unsigned round = 8; round <= (late ? 10u : 11u); ++round) {
    payment_circuit_charge_t c;
    charge(&f, round, &c);
    tt_int_op(payment_circuit_authorize(f.circ, round, &c,
                       round == 8 ? 363000 : 2000+(round-2)*60000), OP_EQ, 0);
  }
  if (late) {
    /* Authorization drives allocation rotation, then funds the moved record. */
    tt_int_op(payment_circuit_get_registration(f.circ, 1, 603000, &snapshot),
              OP_EQ, PAYMENT_CIRCUIT_OBSERVATION_PENDING);
    tt_int_op(payment_circuit_authorize(f.circ, 11, &eleventh, 603000), OP_EQ, 0);
  }
  payment_circuit_tick(f.circ, late ? 603000 : 602000);
  tt_assert(payment_circuit_paid_active(f.circ));
  tt_int_op(payment_circuit_get_registration(f.circ, 1,
            late ? 603000 : 602000, &snapshot),
            OP_EQ, 0);
  tt_u64_op(snapshot.current_round, OP_EQ, 11);
  tt_int_op(snapshot.rounds[0].charge.authorization, OP_EQ,
            PAYMENT_CIRCUIT_CONSUMED);
  tt_int_op(payment_circuit_get_registration(f.circ, 0,
            late ? 603000 : 602000, &snapshot),
            OP_EQ, PAYMENT_CIRCUIT_UNKNOWN_PERIOD);
  tt_int_op(send_request(&f, &m, 603000), OP_EQ, 0);
  tt_int_op(read_reply(&f, &reply), OP_EQ, 0);
  tt_int_op(reply.u.renewed.status, OP_EQ, 1);
  m.u.renew.nonce[0] ^= 1;
  tt_int_op(send_request(&f, &m, 603000), OP_EQ, 0);
  tt_int_op(read_reply(&f, &reply), OP_EQ, 0);
  tt_int_op(reply.u.renewed.status, OP_EQ, 4);
 done:
  fixture_clear();
}

static void
test_payment_circuit_renewal(void *arg)
{
  (void)arg;
  run_renewal(false);
}

static void
test_payment_circuit_renewal_late(void *arg)
{
  (void)arg;
  run_renewal(true);
}

static void
test_payment_circuit_zero_and_framing(void *arg)
{
  (void)arg;
  test_fixture_t f;
  payment_circuit_snapshot_t snapshot;
  payment_profile_message_t m, reply;
  uint8_t wire[PAYMENT_PROFILE_WIRE_LEN];
  tt_int_op(fixture_init_prices(&f, true), OP_EQ, 0);
  m = commit_request(&f);
  tt_int_op(payment_profile_encode(wire, sizeof(wire), &m,
                      f.keys.start_request, f.keys.binding), OP_EQ, 0);
  relay_msg_t msg = {0};
  msg.command = PAYMENT_PROFILE_COMMIT;
  msg.length = sizeof(wire); msg.body = wire; msg.stream_id = 1;
  tt_int_op(payment_circuit_handle_relay(f.circ, &msg, 2000), OP_EQ, 0);
  msg.stream_id = 0; msg.is_relay_early = true;
  tt_int_op(payment_circuit_handle_relay(f.circ, &msg, 2000), OP_EQ, 0);
  msg.is_relay_early = false; msg.length = sizeof(wire)-1;
  tt_int_op(payment_circuit_handle_relay(f.circ, &msg, 2000), OP_EQ, 0);
  msg.length = sizeof(wire); wire[462] ^= 1;
  tt_int_op(payment_circuit_handle_relay(f.circ, &msg, 2000), OP_EQ, 0);
  tt_u64_op(payment_circuit_revision(f.circ), OP_EQ, 1);
  tt_uint_op(reply_count, OP_EQ, 0);
  tt_int_op(payment_circuit_get_admission(f.circ, 0, 2000, &snapshot), OP_EQ,
            PAYMENT_CIRCUIT_UNCONFIRMED);
  tt_int_op(commit_and_reserve(&f, 2000), OP_EQ, 0);
  m = start_request(&f);
  tt_int_op(send_request(&f, &m, 2000), OP_EQ, 0);
  tt_int_op(read_reply(&f, &reply), OP_EQ, 0);
  tt_int_op(reply.u.started.state, OP_EQ, 2);
  tt_assert(!payment_circuit_paid_active(f.circ));
  payment_circuit_charge_t fee, first;
  charge(&f, 0, &fee);
  charge(&f, 1, &first);
  tt_int_op(payment_circuit_authorize(f.circ, 0, &fee, 2000), OP_EQ, 0);
  tt_assert(!payment_circuit_paid_active(f.circ));
  tt_int_op(payment_circuit_authorize(f.circ, 1, &first, 2000), OP_EQ, 0);
  tt_assert(payment_circuit_paid_active(f.circ));
 done:
  fixture_clear();
}

static void
run_free_candidate(bool committed)
{
  test_fixture_t f;
  or_connection_t conn={0}; channel_tls_t channel={0};
  payment_profile_message_t message,received;
  monotime_enable_test_mocking();
  monotime_set_mock_time_nsec(INT64_C(1000000000));
  monotime_coarse_set_mock_time_nsec(INT64_C(1000000000));
  tt_int_op(fixture_init(&f),OP_EQ,0);
  channel.base_.magic=TLS_CHAN_MAGIC; channel.base_.wide_circ_ids=1;
  channel.conn=&conn;
  tt_int_op(free_capacity_circuit_admit(TO_CIRCUIT(f.circ),&conn),OP_EQ,0);
  if (committed) {
    tt_int_op(commit_and_reserve(&f,2000),OP_EQ,0);
    tt_assert(payment_circuit_requires_payment(f.circ));
  }
  monotime_set_mock_time_nsec(INT64_C(32000000000));
  payment_circuit_tick(f.circ,32000);
  if (committed) {
    tt_assert(f.circ->base_.marked_for_close);
    tt_ptr_op(f.circ->payment_keys,OP_EQ,NULL);
  } else {
    tt_assert(!f.circ->base_.marked_for_close);
    tt_assert(!payment_circuit_requires_payment(f.circ));
    tt_int_op(free_capacity_circuit_send(TO_CIRCUIT(f.circ),&channel.base_),OP_EQ,
              FREE_CAPACITY_OK);
    message=commit_request(&f);
    tt_int_op(send_request(&f,&message,32000),OP_EQ,0);
    tt_int_op(read_reply(&f,&received),OP_EQ,0);
    tt_uint_op(received.u.committed.status,OP_EQ,4); /* late COMMIT cannot revive */
    tt_assert(!payment_circuit_requires_payment(f.circ));
  }
 done:
  fixture_clear(); free_capacity_connection_free(&conn);
  (void)payment_resources_free_all(); monotime_disable_test_mocking();
}
static void
test_payment_circuit_free_candidate(void *arg)
{ (void)arg; run_free_candidate(false); }
static void
test_payment_circuit_free_paid_failure(void *arg)
{ (void)arg; run_free_candidate(true); }

#define CIRCUIT_TEST(name) \
  { #name, test_payment_circuit_##name, TT_FORK, NULL, NULL }
struct testcase_t payment_circuit_tests[] = {
  CIRCUIT_TEST(commit_activation),
  CIRCUIT_TEST(refusal_and_expiry),
  CIRCUIT_TEST(round_boundaries),
  CIRCUIT_TEST(renewal),
  CIRCUIT_TEST(renewal_late),
  CIRCUIT_TEST(zero_and_framing),
  CIRCUIT_TEST(free_candidate),
  CIRCUIT_TEST(free_paid_failure),
  END_OF_TESTCASES
};
