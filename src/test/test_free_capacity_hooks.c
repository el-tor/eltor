/* Copyright (c) 2026, The El Tor Project. */
/* See LICENSE for licensing information. */
#define CHANNEL_OBJECT_PRIVATE
#define RELAY_PRIVATE
#define TOR_TIMERS_PRIVATE
#define CIRCUITMUX_EWMA_PRIVATE
#include "orconfig.h"
#include "core/or/or.h"
#include "feature/payment/free_capacity_hooks.h"
#include "feature/payment/payment_resources.h"
#include "feature/payment/payment_circuit.h"
#include "core/or/channel.h"
#include "core/or/channeltls.h"
#include "core/or/circuitlist.h"
#include "core/or/circuit_st.h"
#include "core/or/or_circuit_st.h"
#include "core/or/origin_circuit_st.h"
#include "core/or/or_connection_st.h"
#include "core/or/cell_queue_st.h"
#include "core/or/cell_st.h"
#include "core/or/relay.h"
#include "core/or/circuitmux.h"
#include "core/or/circuitmux_ewma.h"
#include "core/or/scheduler.h"
#include "test/fakechans.h"
#include "lib/evloop/timers.h"
#include "lib/time/compat_time.h"
#include "test/test.h"

static bool paid_active;
static bool
mock_paid_bytes(or_circuit_t *circ, uint32_t bytes, uint64_t now_ms)
{
  (void)circ; (void)bytes; (void)now_ms;
  return true; /* These tests isolate scheduling; financial tests use real keys. */
}
static bool
mock_paid_active(const circuit_t *circ)
{
  (void)circ;
  return paid_active;
}

static void
test_free_hooks_queue_and_teardown(void *arg)
{
  or_circuit_t *circ = NULL;
  or_connection_t conn = {0};
  cell_t cell = {0};
  protocol_budget_t *owner;
  uint32_t with_context, baseline;
  (void)arg;
  monotime_enable_test_mocking();
  monotime_set_mock_time_nsec(INT64_C(1000000000));
  monotime_coarse_set_mock_time_nsec(INT64_C(1000000000));
  timers_initialize();
  baseline = payment_resources_protocol()->arena_used;
  circ = or_circuit_new(0, NULL);
  tt_int_op(free_capacity_circuit_admit(TO_CIRCUIT(circ), &conn), OP_EQ, 0);
  tt_int_op(free_capacity_circuit_admit(TO_CIRCUIT(circ), &conn), OP_EQ, -1);
  owner = payment_resources_protocol();
  with_context = owner->arena_used;
  tt_uint_op(with_context, OP_GT, 0);
  cell.command = CELL_RELAY;
  for (unsigned i = 0; i < 32; ++i) {
    cell_queue_t *queue = i % 2 ? &circ->p_chan_cells : &circ->base_.n_chan_cells;
    cell_queue_append_packed_copy(TO_CIRCUIT(circ), queue, i % 2, &cell, 1, 0);
  }
  tt_uint_op(payment_resources_free()->queued_bytes, OP_EQ,
              32 * packed_cell_mem_cost());
  /* Independent direction disposal retains the other direction's receipts. */
  cell_queue_clear(&circ->p_chan_cells);
  tt_uint_op(payment_resources_free()->queued_bytes, OP_EQ,
              16 * packed_cell_mem_cost());
  /* Expired cells still release actual allocations without clock/refill. */
  monotime_set_mock_time_nsec(INT64_C(7000000000));
  cell_queue_clear(&circ->base_.n_chan_cells);
  tt_uint_op(payment_resources_free()->queued_bytes, OP_EQ, 0);
  tt_uint_op(owner->arena_used, OP_EQ, with_context);
  circuit_free_all();
  circ = NULL;
  tt_uint_op(payment_resources_free()->live_circuits, OP_EQ, 0);
  free_capacity_connection_free(&conn);
  tt_uint_op(owner->arena_used, OP_EQ, baseline);
  tt_int_op(payment_resources_free_all(), OP_EQ, 0);
 done:
  circuit_free_all();
  free_capacity_connection_free(&conn);
  (void)payment_resources_free_all();
  timers_shutdown();
  monotime_disable_test_mocking();
}

static void
test_free_hooks_send_and_paid(void *arg)
{
  MOCK(free_capacity_paid_data_active, mock_paid_active);
  MOCK(payment_circuit_account_bytes, mock_paid_bytes);
  paid_active = true;
  or_circuit_t *circ = NULL;
  or_connection_t previous = {0}, next = {0};
  channel_tls_t prev_chan = {0}, next_chan = {0};
  uint64_t before;
  (void)arg;
  monotime_enable_test_mocking();
  monotime_set_mock_time_nsec(INT64_C(1000000000));
  monotime_coarse_set_mock_time_nsec(INT64_C(1000000000));
  timers_initialize();
  prev_chan.base_.magic = next_chan.base_.magic = TLS_CHAN_MAGIC;
  prev_chan.base_.wide_circ_ids = next_chan.base_.wide_circ_ids = 1;
  prev_chan.conn = &previous;
  next_chan.conn = &next;
  circ = or_circuit_new(0, NULL);
  tt_int_op(free_capacity_circuit_admit(TO_CIRCUIT(circ), &previous), OP_EQ, 0);
  /* Both physical links consume one common circuit allowance. Loopback is
   * deliberately irrelevant: no native local-address rate-limit exemption. */
  for (unsigned i = 0; i < 128; ++i)
    tt_int_op(free_capacity_circuit_send(TO_CIRCUIT(circ),
      i % 2 ? &prev_chan.base_ : &next_chan.base_), OP_EQ, FREE_CAPACITY_OK);
  before = payment_resources_free()->sent_bytes;
  tt_int_op(free_capacity_circuit_send(TO_CIRCUIT(circ), &next_chan.base_),
            OP_EQ, FREE_CAPACITY_WAIT);
  tt_u64_op(payment_resources_free()->sent_bytes, OP_EQ, before);
  monotime_set_mock_time_nsec(INT64_C(1500000000));
  tt_int_op(free_capacity_circuit_send(TO_CIRCUIT(circ), &next_chan.base_),
            OP_EQ, FREE_CAPACITY_OK);
  tt_u64_op(payment_resources_free()->sent_bytes, OP_EQ, before + 2053);
  /* Activating paid authority does not refill the process buckets. */
  before = payment_resources_free()->bytes.credit_milli;
  free_capacity_circuit_paid(TO_CIRCUIT(circ));
  tt_u64_op(payment_resources_free()->bytes.credit_milli, OP_EQ, before);
  tt_int_op(free_capacity_circuit_send(TO_CIRCUIT(circ), &next_chan.base_),
            OP_EQ, FREE_CAPACITY_OK);
  tt_u64_op(payment_resources_free()->bytes.credit_milli, OP_EQ, before);
 done:
  circuit_free_all();
  free_capacity_connection_free(&previous);
  free_capacity_connection_free(&next);
  (void)payment_resources_free_all();
  timers_shutdown();
  monotime_disable_test_mocking();
  UNMOCK(free_capacity_paid_data_active);
  UNMOCK(payment_circuit_account_bytes);
}

static void
test_free_hooks_lower_arena(void *arg)
{
  protocol_budget_limits_t limits;
  or_connection_t conn = {0};
  or_circuit_t *circ = NULL;
  (void)arg;
  protocol_budget_default_limits(&limits);
  limits.arena_bytes = 64;
  limits.max_slot_bytes = 64;
  tt_int_op(payment_resources_configure(&limits), OP_EQ, 0);
  circ = or_circuit_new(0, NULL);
  tt_int_op(free_capacity_circuit_admit(TO_CIRCUIT(circ), &conn), OP_EQ, -1);
  tt_ptr_op(circ->base_.free_capacity, OP_EQ, NULL);
  tt_ptr_op(conn.free_capacity, OP_EQ, NULL);
  tt_uint_op(payment_resources_protocol()->arena_used, OP_EQ, 0);
 done:
  circuit_free_all();
  free_capacity_connection_free(&conn);
  (void)payment_resources_free_all();
}

static unsigned teardown_writes;
static int
write_teardown(channel_t *base, cell_t *cell)
{
  channel_tls_t *chan = BASE_CHAN_TO_TLS(base);
  if (cell->command == CELL_DESTROY &&
      free_capacity_wire_send(chan->conn, cell->circ_id,
          get_cell_network_size(base->wide_circ_ids), true, cell->command)) {
    ++teardown_writes;
    return 1;
  }
  return 0;
}

static void
test_free_hooks_scheduler_and_ingress(void *arg)
{
  or_circuit_t *circ = NULL, *ordinary = NULL;
  or_connection_t conn = {0};
  channel_tls_t *chan = NULL;
  cell_t cell = { .command = CELL_RELAY };
  uint64_t before;
  (void)arg;
  MOCK(scheduler_channel_has_waiting_cells,
       scheduler_channel_has_waiting_cells_mock);
  MOCK(scheduler_release_channel, scheduler_release_channel_mock);
  monotime_enable_test_mocking();
  monotime_set_mock_time_nsec(INT64_C(1000000000));
  monotime_coarse_set_mock_time_nsec(INT64_C(1000000000));
  timers_initialize();
  cell_ewma_initialize_ticks();
  chan = tor_realloc(new_fake_channel(), sizeof(*chan));
  chan->base_.magic = TLS_CHAN_MAGIC;
  chan->base_.wide_circ_ids = true;
  chan->conn = &conn;
  chan->base_.write_cell = write_teardown;
  teardown_writes = 0;
  conn.wide_circ_ids = true;
  conn.chan = chan;
  circ = or_circuit_new(10, &chan->base_);
  ordinary = or_circuit_new(11, &chan->base_);
  circ->base_.purpose = ordinary->base_.purpose = CIRCUIT_PURPOSE_OR;
  circ->base_.state = ordinary->base_.state = CIRCUIT_STATE_ONIONSKIN_PENDING;
  tt_int_op(free_capacity_circuit_admit(TO_CIRCUIT(circ), &conn), OP_EQ, 0);
  /* Serialized ingress includes the same per-circuit fixed-cell bucket as
   * egress, before relay crypto/dispatch; no local-address exemption. */
  for (unsigned i = 0; i < 128; ++i)
    tt_assert(free_capacity_wire_receive(&conn, 10, 2053, true, CELL_RELAY));
  before = payment_resources_free()->received_bytes;
  tt_u64_op(before, OP_EQ, 128 * 2053 + 2053);
  cell_queue_append_packed_copy(TO_CIRCUIT(circ), &circ->p_chan_cells,
                                0, &cell, 1, 0);
  cell_queue_append_packed_copy(TO_CIRCUIT(ordinary), &ordinary->p_chan_cells,
                                0, &cell, 1, 0);
  circuitmux_set_num_cells(chan->base_.cmux, TO_CIRCUIT(circ), 1);
  circuitmux_set_num_cells(chan->base_.cmux, TO_CIRCUIT(ordinary), 1);
  tt_int_op(free_capacity_circuit_send(TO_CIRCUIT(circ), &chan->base_),
            OP_EQ, FREE_CAPACITY_WAIT);
  tt_assert(!circuitmux_is_circuit_active(chan->base_.cmux, TO_CIRCUIT(circ)));
  tt_assert(circuitmux_is_circuit_active(chan->base_.cmux,
                                        TO_CIRCUIT(ordinary)));
  /* An append while waiting cannot reactivate the blocked circuit. */
  circuitmux_set_num_cells(chan->base_.cmux, TO_CIRCUIT(circ), 1);
  free_capacity_circuit_queued(TO_CIRCUIT(circ));
  tt_assert(!circuitmux_is_circuit_active(chan->base_.cmux, TO_CIRCUIT(circ)));
  monotime_set_mock_time_nsec(INT64_C(1501000000));
  monotime_coarse_set_mock_time_nsec(INT64_C(1501000000));
  timers_run_pending();
  tt_assert(circuitmux_is_circuit_active(chan->base_.cmux, TO_CIRCUIT(circ)));
  /* Exactly one refilled cell sends through the real pre-pop scheduler hook.
   * The ordinary circuit can be selected too; both remain bounded. */
  tt_int_op(channel_flush_from_first_active_circuit(&chan->base_, 2), OP_EQ, 2);
  tt_uint_op(payment_resources_free()->queued_bytes, OP_EQ, 0);
  tt_u64_op(payment_resources_free()->sent_bytes, OP_EQ, 2053);
  /* At fixed time no second incoming stateful cell can continue the circuit. */
  tt_assert(!free_capacity_wire_receive(&conn, 10, 2053, true, CELL_RELAY));
  tt_assert(circ->base_.marked_for_close);
  circuit_close_all_marked();
  circ = NULL;
  tt_uint_op(teardown_writes, OP_EQ, 1);
  tt_uint_op(circuitmux_num_cells(chan->base_.cmux), OP_EQ, 0);
  tt_u64_op(payment_resources_free()->sent_bytes, OP_EQ, 4106);
  tt_u64_op(payment_resources_free()->received_bytes, OP_EQ, before + 2053);
 done:
  circuit_free_all();
  free_capacity_connection_free(&conn);
  conn.chan = NULL;
  if (chan) free_fake_channel(&chan->base_);
  (void)payment_resources_free_all();
  timers_shutdown();
  monotime_disable_test_mocking();
  UNMOCK(scheduler_channel_has_waiting_cells);
  UNMOCK(scheduler_release_channel);
}

static void
test_free_hooks_provisional(void *arg)
{
  or_circuit_t *circ = NULL;
  or_connection_t conn = {0};
  free_capacity_queue_ticket_t ticket;
  uint64_t credit;
  channel_tls_t chan = {0};
  (void)arg;
  monotime_enable_test_mocking();
  monotime_set_mock_time_nsec(INT64_C(1000000000));
  timers_initialize();
  conn.wide_circ_ids = true;
  circ = or_circuit_new(0, NULL);
  tt_int_op(free_capacity_circuit_prepare(TO_CIRCUIT(circ), &conn), OP_EQ, 0);
  chan.base_.magic = TLS_CHAN_MAGIC;
  chan.base_.wide_circ_ids = true;
  chan.conn = &conn;
  tt_int_op(free_capacity_circuit_setup_received(TO_CIRCUIT(circ), &chan.base_),
            OP_EQ, 0);
  tt_int_op(free_capacity_circuit_setup_received(TO_CIRCUIT(circ), &chan.base_),
            OP_EQ, 0);
  tt_u64_op(payment_resources_free()->received_bytes, OP_EQ, 2053);
  credit = payment_resources_free()->admissions.credit_milli;
  tt_uint_op(payment_resources_free()->live_circuits, OP_EQ, 1);
  tt_int_op(free_capacity_cell_reserve(TO_CIRCUIT(circ), &ticket), OP_EQ, -1);
  tt_uint_op(ticket.serial, OP_EQ, 0);
  free_capacity_circuit_paid(TO_CIRCUIT(circ));
  tt_int_op(free_capacity_cell_reserve(TO_CIRCUIT(circ), &ticket), OP_EQ, -1);
  /* Authenticated completion performs no allocation/refill or new admission. */
  uint32_t memory = payment_resources_protocol()->arena_used;
  tt_int_op(free_capacity_circuit_confirm(TO_CIRCUIT(circ)), OP_EQ, 0);
  tt_uint_op(payment_resources_protocol()->arena_used, OP_EQ, memory);
  tt_int_op(free_capacity_cell_reserve(TO_CIRCUIT(circ), &ticket), OP_EQ, 0);
  free_capacity_cell_release(TO_CIRCUIT(circ), &ticket);
  free_capacity_circuit_free(TO_CIRCUIT(circ));
  tt_uint_op(payment_resources_free()->live_circuits, OP_EQ, 0);
  tt_u64_op(payment_resources_free()->admissions.credit_milli, OP_EQ, credit);
 done:
  circuit_free_all();
  free_capacity_connection_free(&conn);
  (void)payment_resources_free_all();
  timers_shutdown();
  monotime_disable_test_mocking();
}

static void
test_free_hooks_provisional_queue(void *arg)
{
  (void)arg;
  origin_circuit_t *circ = NULL;
  or_connection_t conn = {0};
  channel_tls_t *chan = NULL;
  cell_t cell = { .command = CELL_CREATE2, .circ_id = 10 };
  free_capacity_queue_ticket_t ticket;
  MOCK(scheduler_channel_has_waiting_cells,
       scheduler_channel_has_waiting_cells_mock);
  MOCK(scheduler_release_channel, scheduler_release_channel_mock);
  monotime_enable_test_mocking();
  monotime_set_mock_time_nsec(INT64_C(1000000000));
  monotime_coarse_set_mock_time_nsec(INT64_C(1000000000));
  timers_initialize(); cell_ewma_initialize_ticks();
  chan = tor_realloc(new_fake_channel(), sizeof(*chan));
  chan->base_.magic = TLS_CHAN_MAGIC;
  chan->base_.wide_circ_ids = conn.wide_circ_ids = true;
  chan->conn = &conn; conn.chan = chan;
  circ = origin_circuit_new(); circ->base_.purpose = CIRCUIT_PURPOSE_C_GENERAL;
  circuit_set_n_circid_chan(TO_CIRCUIT(circ), 10, &chan->base_);
  tt_int_op(free_capacity_circuit_prepare(TO_CIRCUIT(circ), &conn), OP_EQ, 0);
  tt_int_op(free_capacity_cell_reserve(TO_CIRCUIT(circ), &ticket), OP_EQ, -1);
  /* Native first CREATE uses the packed circuit queue before authenticated
   * CREATED can confirm the context. It still owns one bounded receipt. */
  cell_queue_append_packed_copy(TO_CIRCUIT(circ), &circ->base_.n_chan_cells,
                               1, &cell, 1, 0);
  tt_assert(!circ->base_.marked_for_close);
  tt_uint_op(payment_resources_free()->queued_bytes, OP_EQ, packed_cell_mem_cost());
  circuitmux_set_num_cells(chan->base_.cmux, TO_CIRCUIT(circ), 1);
  tt_int_op(channel_flush_from_first_active_circuit(&chan->base_, 1), OP_EQ, 1);
  tt_uint_op(payment_resources_free()->queued_bytes, OP_EQ, 0);
  tt_u64_op(payment_resources_free()->sent_bytes, OP_EQ, 2053);
  tt_uint_op(circ->base_.n_chan_cells.n, OP_EQ, 0);
  cell_queue_append_packed_copy(TO_CIRCUIT(circ), &circ->base_.n_chan_cells,
                               1, &cell, 1, 0);
  circuitmux_set_num_cells(chan->base_.cmux, TO_CIRCUIT(circ), 1);
  /* A locally generated payment-control annotation is not a setup command and
   * cannot bypass authentication, even at the otherwise permitted FIFO head. */
  tt_int_op(free_capacity_circuit_send_control(TO_CIRCUIT(circ), &chan->base_,
                                               true), OP_EQ, FREE_CAPACITY_CLOSE);
  tt_assert(circ->base_.marked_for_close);
  /* Actual queued backing remains owned until cleanup, but the native flush
   * must return instead of spinning on this marked circuit's refused head. */
  tt_int_op(channel_flush_from_first_active_circuit(&chan->base_, 1), OP_EQ, 0);
  tt_uint_op(circuitmux_num_cells(chan->base_.cmux), OP_EQ, 0);
  tt_uint_op(circ->base_.n_chan_cells.n, OP_EQ, 1);
 done:
  circuit_free_all(); free_capacity_connection_free(&conn); conn.chan = NULL;
  if (chan) free_fake_channel(&chan->base_);
  (void)payment_resources_free_all(); timers_shutdown();
  monotime_disable_test_mocking();
  UNMOCK(scheduler_channel_has_waiting_cells); UNMOCK(scheduler_release_channel);
}

static void
test_free_hooks_paid_queue_expiry(void *arg)
{
  or_circuit_t *circ = NULL;
  or_connection_t conn = {0};
  cell_t cell = { .command = CELL_RELAY };
  (void)arg;
  monotime_enable_test_mocking();
  monotime_set_mock_time_nsec(INT64_C(1000000000));
  monotime_coarse_set_mock_time_nsec(INT64_C(1000000000));
  timers_initialize();
  circ = or_circuit_new(0, NULL);
  circ->base_.purpose = CIRCUIT_PURPOSE_OR;
  circ->base_.state = CIRCUIT_STATE_ONIONSKIN_PENDING;
  tt_int_op(free_capacity_circuit_admit(TO_CIRCUIT(circ), &conn), OP_EQ, 0);
  cell_queue_append_packed_copy(TO_CIRCUIT(circ), &circ->p_chan_cells,
                                0, &cell, 1, 0);
  free_capacity_circuit_queued(TO_CIRCUIT(circ));
  free_capacity_circuit_paid(TO_CIRCUIT(circ));
  monotime_set_mock_time_nsec(INT64_C(6001000000));
  monotime_coarse_set_mock_time_nsec(INT64_C(6001000000));
  timers_run_pending();
  tt_assert(circ->base_.marked_for_close);
  circuit_close_all_marked();
  circ = NULL;
  tt_uint_op(payment_resources_free()->queued_bytes, OP_EQ, 0);
  tt_uint_op(payment_resources_free()->live_circuits, OP_EQ, 0);
  timers_run_pending(); /* No stale queue deadline may busy-loop. */
 done:
  circuit_free_all();
  free_capacity_connection_free(&conn);
  (void)payment_resources_free_all();
  timers_shutdown();
  monotime_disable_test_mocking();
}

/* A single relay circuit can hold encrypted bulk on one direction while
 * the other direction's payment control head remains runnable. The annotation
 * is local queue metadata; public queue wrappers default to bulk. */
static void
test_free_hooks_paid_grace_fifo(void *arg)
{
  or_circuit_t *circ = NULL;
  or_connection_t previous = {0}, next = {0};
  channel_tls_t *p = NULL, *n = NULL;
  cell_t cell = { .command = CELL_RELAY };
  packed_cell_t *first, *second;
  uint64_t credit, before;
  (void)arg;
  MOCK(scheduler_channel_has_waiting_cells,
       scheduler_channel_has_waiting_cells_mock);
  MOCK(scheduler_release_channel, scheduler_release_channel_mock);
  MOCK(free_capacity_paid_data_active, mock_paid_active);
  MOCK(payment_circuit_account_bytes, mock_paid_bytes);
  paid_active = true;
  monotime_enable_test_mocking();
  monotime_set_mock_time_nsec(INT64_C(1000000000));
  monotime_coarse_set_mock_time_nsec(INT64_C(1000000000));
  timers_initialize();
  cell_ewma_initialize_ticks();
  p = tor_realloc(new_fake_channel(), sizeof(*p));
  n = tor_realloc(new_fake_channel(), sizeof(*n));
  p->base_.magic = n->base_.magic = TLS_CHAN_MAGIC;
  p->base_.wide_circ_ids = n->base_.wide_circ_ids = true;
  p->conn = &previous; n->conn = &next;
  previous.chan = p; next.chan = n;
  circ = or_circuit_new(10, &p->base_);
  circ->base_.purpose = CIRCUIT_PURPOSE_OR;
  circ->base_.state = CIRCUIT_STATE_ONIONSKIN_PENDING;
  circuit_set_n_circid_chan(TO_CIRCUIT(circ), 12, &n->base_);
  tt_int_op(free_capacity_circuit_admit(TO_CIRCUIT(circ), &previous), OP_EQ, 0);
  free_capacity_circuit_paid(TO_CIRCUIT(circ));
  /* Queue while ACTIVE, then enter GRACE: original allocations are adopted. */
  cell_queue_append_packed_copy(TO_CIRCUIT(circ), &circ->p_chan_cells,
                                0, &cell, 1, 0);
  first = TOR_SIMPLEQ_FIRST(&circ->p_chan_cells.head);
  tt_assert(!first->payment_control);
  cell_queue_append_packed_copy(TO_CIRCUIT(circ), &circ->p_chan_cells,
                                0, &cell, 1, 0);
  second = TOR_SIMPLEQ_NEXT(first, next);
  second->payment_control = true;
  cell_queue_append_packed_copy(TO_CIRCUIT(circ), &circ->base_.n_chan_cells,
                                1, &cell, 1, 0);
  TOR_SIMPLEQ_FIRST(&circ->base_.n_chan_cells.head)->payment_control = true;
  cell_queue_append_packed_copy(TO_CIRCUIT(circ), &circ->base_.n_chan_cells,
                                1, &cell, 1, 0);
  TOR_SIMPLEQ_NEXT(TOR_SIMPLEQ_FIRST(&circ->base_.n_chan_cells.head), next)
    ->payment_control = true;
  tt_uint_op(payment_resources_free()->queued_bytes, OP_EQ, 0);
  circuitmux_set_num_cells(p->base_.cmux, TO_CIRCUIT(circ), 2);
  circuitmux_set_num_cells(n->base_.cmux, TO_CIRCUIT(circ), 2);
  paid_active = false;
  free_capacity_circuit_queued(TO_CIRCUIT(circ));
  tt_uint_op(payment_resources_free()->queued_bytes, OP_EQ,
              4 * packed_cell_mem_cost());
  tt_assert(!circuitmux_is_circuit_active(p->base_.cmux, TO_CIRCUIT(circ)));
  tt_assert(circuitmux_is_circuit_active(n->base_.cmux, TO_CIRCUIT(circ)));
  tt_int_op(channel_flush_from_first_active_circuit(&p->base_, 3), OP_EQ, 0);
  tt_ptr_op(TOR_SIMPLEQ_FIRST(&circ->p_chan_cells.head), OP_EQ, first);
  before = payment_resources_free()->sent_bytes;
  tt_int_op(channel_flush_from_first_active_circuit(&n->base_, 3), OP_EQ, 2);
  tt_u64_op(payment_resources_free()->sent_bytes, OP_EQ, before + 4106);
  tt_uint_op(payment_resources_free()->queued_bytes, OP_EQ,
              2 * packed_cell_mem_cost());
  /* Restoring independently verified ACTIVE resumes the original FIFO. */
  credit = payment_resources_free()->bytes.credit_milli;
  paid_active = true;
  free_capacity_circuit_paid(TO_CIRCUIT(circ));
  tt_int_op(channel_flush_from_first_active_circuit(&p->base_, 3), OP_EQ, 2);
  tt_uint_op(payment_resources_free()->queued_bytes, OP_EQ, 0);
  tt_u64_op(payment_resources_free()->bytes.credit_milli, OP_EQ, credit);
  /* A paid circuit older than the free lifetime gets only a bounded hold;
   * GRACE never regains the tiny free circuit allowance. */
  monotime_set_mock_time_nsec(INT64_C(602000000000));
  monotime_coarse_set_mock_time_nsec(INT64_C(602000000000));
  paid_active = false;
  cell_queue_append_packed_copy(TO_CIRCUIT(circ), &circ->p_chan_cells,
                                0, &cell, 1, 0);
  free_capacity_circuit_queued(TO_CIRCUIT(circ));
  tt_assert(!circ->base_.marked_for_close);
  tt_int_op(free_capacity_circuit_send(TO_CIRCUIT(circ), &p->base_),
            OP_EQ, FREE_CAPACITY_WAIT);
  monotime_set_mock_time_nsec(INT64_C(607001000000));
  monotime_coarse_set_mock_time_nsec(INT64_C(607001000000));
  timers_run_pending();
  tt_assert(circ->base_.marked_for_close);
  circuit_close_all_marked(); circ = NULL;
  tt_uint_op(payment_resources_free()->queued_bytes, OP_EQ, 0);
 done:
  circuit_free_all();
  free_capacity_connection_free(&previous);
  free_capacity_connection_free(&next);
  previous.chan = next.chan = NULL;
  if (p) free_fake_channel(&p->base_);
  if (n) free_fake_channel(&n->base_);
  (void)payment_resources_free_all();
  timers_shutdown();
  monotime_disable_test_mocking();
  UNMOCK(scheduler_channel_has_waiting_cells);
  UNMOCK(scheduler_release_channel);
  UNMOCK(free_capacity_paid_data_active);
  UNMOCK(payment_circuit_account_bytes);
}

static void
paid_grace_reject(bool age)
{
  or_circuit_t *circ = NULL;
  or_connection_t conn = {0};
  cell_t cell = { .command = CELL_RELAY };
  (void)age;
  MOCK(free_capacity_paid_data_active, mock_paid_active);
  MOCK(payment_circuit_account_bytes, mock_paid_bytes);
  paid_active = true;
  monotime_enable_test_mocking();
  monotime_set_mock_time_nsec(INT64_C(1000000000));
  monotime_coarse_set_mock_time_nsec(INT64_C(1000000000));
  timers_initialize();
  circ = or_circuit_new(0, NULL);
  circ->base_.purpose = CIRCUIT_PURPOSE_OR;
  circ->base_.state = CIRCUIT_STATE_ONIONSKIN_PENDING;
  tt_int_op(free_capacity_circuit_admit(TO_CIRCUIT(circ), &conn), OP_EQ, 0);
  free_capacity_circuit_paid(TO_CIRCUIT(circ));
  unsigned count = age ? 1 : 33;
  for (unsigned i = 0; i < count; ++i)
    cell_queue_append_packed_copy(TO_CIRCUIT(circ), &circ->p_chan_cells,
                                  0, &cell, 1, 0);
  tt_uint_op(payment_resources_free()->queued_bytes, OP_EQ, 0);
  if (age) {
    /* No timer has run: GRACE adoption must retain the allocation's original
     * age and refuse it immediately, rather than grant a fresh five seconds. */
    monotime_set_mock_time_nsec(INT64_C(6001000000));
    monotime_coarse_set_mock_time_nsec(INT64_C(6001000000));
  }
  paid_active = false;
  free_capacity_circuit_queued(TO_CIRCUIT(circ));
  tt_assert(circ->base_.marked_for_close);
  tt_uint_op(circ->p_chan_cells.n, OP_EQ, count);
  /* An oversized transition can charge its first 32 allocations only; closure
   * destroys every native allocation and releases precisely those receipts. */
  circuit_close_all_marked(); circ = NULL;
  tt_uint_op(payment_resources_free()->queued_bytes, OP_EQ, 0);
  tt_uint_op(payment_resources_free()->live_circuits, OP_EQ, 0);
 done:
  circuit_free_all();
  free_capacity_connection_free(&conn);
  (void)payment_resources_free_all();
  timers_shutdown(); monotime_disable_test_mocking();
  UNMOCK(free_capacity_paid_data_active);
  UNMOCK(payment_circuit_account_bytes);
}
static void
test_free_hooks_paid_grace_overflow(void *arg)
{
  (void)arg; paid_grace_reject(false);
}
static void
test_free_hooks_paid_grace_original_age(void *arg)
{
  (void)arg; paid_grace_reject(true);
}

#define HOOK_TEST(name) { #name, test_free_hooks_##name, TT_FORK, NULL, NULL }
struct testcase_t free_capacity_hooks_tests[] = {
  HOOK_TEST(queue_and_teardown),
  HOOK_TEST(send_and_paid),
  HOOK_TEST(lower_arena),
  HOOK_TEST(scheduler_and_ingress),
  HOOK_TEST(provisional),
  HOOK_TEST(provisional_queue),
  HOOK_TEST(paid_queue_expiry),
  HOOK_TEST(paid_grace_fifo),
  HOOK_TEST(paid_grace_overflow),
  HOOK_TEST(paid_grace_original_age),
  END_OF_TESTCASES
};
