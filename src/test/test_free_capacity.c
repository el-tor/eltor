/* Copyright (c) 2026, The El Tor Project. */
/* See LICENSE for licensing information. */
#include "orconfig.h"
#include "core/or/or.h"
#include "feature/payment/free_capacity.h"
#include "test/test.h"

static void
test_free_capacity_refill(void *arg)
{
  free_capacity_t owner;
  free_capacity_conn_t conn;
  free_capacity_circuit_t circ = {0};
  (void)arg;
  free_capacity_init(&owner, 1000);
  tt_int_op(free_capacity_conn_init(&conn, &owner, 1000), OP_EQ,
            FREE_CAPACITY_OK);
  tt_int_op(free_capacity_admit(&conn, &circ, 1000), OP_EQ, FREE_CAPACITY_OK);
  tt_u64_op(circ.cells.credit_milli, OP_EQ, 128000);
  /* A forwarded cell costs one receive and one send. */
  tt_int_op(free_capacity_receive(&circ, &conn, 64, 64 * 2053, 1000), OP_EQ,
            FREE_CAPACITY_OK);
  tt_int_op(free_capacity_send(&circ, &conn, 64, 64 * 2053, 1000), OP_EQ,
            FREE_CAPACITY_OK);
  tt_int_op(free_capacity_send(&circ, &conn, 1, 2053, 1499), OP_EQ,
            FREE_CAPACITY_WAIT);
  tt_u64_op(circ.cells.credit_milli, OP_EQ, 998);
  tt_int_op(free_capacity_send(&circ, &conn, 1, 2053, 1500), OP_EQ,
            FREE_CAPACITY_OK);
  tt_u64_op(circ.cells.credit_milli, OP_EQ, 0);
  /* Tiny repeated clock steps retain fractions; no one-second truncation. */
  for (unsigned i = 1501; i < 2000; ++i)
    tt_int_op(free_capacity_check(&circ, i), OP_EQ, FREE_CAPACITY_OK);
  tt_int_op(free_capacity_send(&circ, &conn, 1, 2053, 2000), OP_EQ,
            FREE_CAPACITY_OK);
  tt_int_op(free_capacity_check(&circ, 66000), OP_EQ, FREE_CAPACITY_OK);
  tt_u64_op(circ.cells.credit_milli, OP_EQ, 128000);
  tt_int_op(free_capacity_check(&circ, 100000), OP_EQ, FREE_CAPACITY_OK);
  tt_u64_op(circ.cells.credit_milli, OP_EQ, 128000);
 done:
  free_capacity_release(&circ);
}

static void
test_free_capacity_atomic_and_received(void *arg)
{
  free_capacity_t owner;
  free_capacity_conn_t conn;
  free_capacity_circuit_t circ = {0};
  uint64_t cells, global_bytes, connection_bytes;
  (void)arg;
  free_capacity_init(&owner, 0);
  tt_int_op(free_capacity_conn_init(&conn, &owner, 0), OP_EQ,
            FREE_CAPACITY_OK);
  tt_int_op(free_capacity_admit(&conn, &circ, 0), OP_EQ, FREE_CAPACITY_OK);
  cells = circ.cells.credit_milli;
  global_bytes = owner.bytes.credit_milli;
  connection_bytes = conn.bytes.credit_milli;
  /* Oversized outbound work is refused without partial debit or overflow. */
  tt_int_op(free_capacity_send(&circ, &conn, 1, UINT64_MAX, 0), OP_EQ,
            FREE_CAPACITY_WAIT);
  tt_u64_op(circ.cells.credit_milli, OP_EQ, cells);
  tt_u64_op(owner.bytes.credit_milli, OP_EQ, global_bytes);
  tt_u64_op(conn.bytes.credit_milli, OP_EQ, connection_bytes);
  tt_int_op(free_capacity_send(&circ, &conn, UINT64_MAX, 1, 0), OP_EQ,
            FREE_CAPACITY_WAIT);
  tt_u64_op(owner.bytes.credit_milli, OP_EQ, global_bytes);
  /* Rejected physical ingress remains charged, and tells caller to CLOSE,
   * never to drop an encrypted RELAY cell and continue. */
  tt_int_op(free_capacity_receive(&circ, &conn, UINT64_MAX, UINT64_MAX, 0), OP_EQ,
            FREE_CAPACITY_CLOSE);
  tt_u64_op(circ.cells.credit_milli, OP_EQ, 0);
  tt_u64_op(conn.bytes.credit_milli, OP_EQ, 0);
  tt_u64_op(owner.bytes.credit_milli, OP_EQ, 0);
  tt_u64_op(owner.received_bytes, OP_EQ, UINT64_MAX);
  tt_int_op(free_capacity_receive(&circ, &conn, 0, 1, 0), OP_EQ,
            FREE_CAPACITY_CLOSE);
  tt_u64_op(owner.received_bytes, OP_EQ, UINT64_MAX);
  tt_int_op(free_capacity_send(&circ, &conn, 1, 2053, 10000), OP_EQ,
            FREE_CAPACITY_CLOSE);
 done:
  free_capacity_release(&circ);
}

static void
test_free_capacity_aggregate(void *arg)
{
  free_capacity_t owner;
  free_capacity_conn_t conn[5];
  free_capacity_circuit_t circ[5] = {{0}};
  (void)arg;
  free_capacity_init(&owner, 0);
  for (unsigned i = 0; i < 5; ++i) {
    tt_int_op(free_capacity_conn_init(&conn[i], &owner, 0), OP_EQ,
              FREE_CAPACITY_OK);
    tt_int_op(free_capacity_admit(&conn[i], &circ[i], 0), OP_EQ,
              FREE_CAPACITY_OK);
  }
  for (unsigned i = 0; i < 4; ++i) {
    /* Fixed cells and variable-cell traffic share the byte budget. */
    tt_int_op(free_capacity_receive(&circ[i], &conn[i], 1, 1048576, 0), OP_EQ,
              FREE_CAPACITY_OK);
    tt_int_op(free_capacity_send(&circ[i], &conn[i], 0, 1048576, 0), OP_EQ,
              FREE_CAPACITY_OK);
    tt_int_op(free_capacity_send(&circ[i], &conn[i], 0, 1, 0), OP_EQ,
              FREE_CAPACITY_WAIT);
  }
  tt_u64_op(owner.bytes.credit_milli, OP_EQ, 0);
  /* A fresh connection/circuit has local credit but cannot reset process. */
  tt_int_op(free_capacity_send(&circ[4], &conn[4], 1, 2053, 0), OP_EQ,
            FREE_CAPACITY_WAIT);
  tt_u64_op(circ[4].cells.credit_milli, OP_EQ, 128000);
  /* Exactly 4 MiB process refill, 1 MiB per connection after 1 second. */
  for (unsigned i = 0; i < 4; ++i)
    tt_int_op(free_capacity_link_send(&conn[i], 1048576, 1000), OP_EQ,
              FREE_CAPACITY_OK);
  tt_int_op(free_capacity_link_send(&conn[4], 1, 1000), OP_EQ,
            FREE_CAPACITY_WAIT);
  tt_u64_op(owner.received_bytes, OP_EQ, 4 * 1048576);
  tt_u64_op(owner.sent_bytes, OP_EQ, 8 * 1048576);
 done:
  for (unsigned i = 0; i < 5; ++i)
    free_capacity_release(&circ[i]);
}

static void
test_free_capacity_admission(void *arg)
{
  free_capacity_t owner;
  free_capacity_conn_t conn[5];
  free_capacity_circuit_t circ[34] = {{0}};
  (void)arg;
  free_capacity_init(&owner, 0);
  for (unsigned i = 0; i < 5; ++i)
    tt_int_op(free_capacity_conn_init(&conn[i], &owner, 0), OP_EQ,
              FREE_CAPACITY_OK);
  for (unsigned i = 0; i < 8; ++i)
    tt_int_op(free_capacity_admit(&conn[0], &circ[i], 0), OP_EQ,
              FREE_CAPACITY_OK);
  tt_int_op(free_capacity_admit(&conn[0], &circ[8], 0), OP_EQ,
            FREE_CAPACITY_REFUSE);
  tt_u64_op(owner.admissions.credit_milli, OP_EQ, 24000);
  for (unsigned i = 8; i < 32; ++i)
    tt_int_op(free_capacity_admit(&conn[i / 8], &circ[i], 0), OP_EQ,
              FREE_CAPACITY_OK);
  tt_int_op(free_capacity_admit(&conn[4], &circ[32], 0), OP_EQ,
            FREE_CAPACITY_REFUSE);
  tt_uint_op(owner.live_circuits, OP_EQ, 32);
  tt_int_op(free_capacity_admit(&conn[4], &circ[32], 62), OP_EQ,
            FREE_CAPACITY_REFUSE);
  tt_int_op(free_capacity_admit(&conn[4], &circ[32], 63), OP_EQ,
            FREE_CAPACITY_OK);
  tt_int_op(free_capacity_admit(&conn[4], &circ[32], 63), OP_EQ,
            FREE_CAPACITY_BAD_STATE);
  /* At 250 ms connection 0 has exactly one new admission token. */
  tt_int_op(free_capacity_admit(&conn[0], &circ[33], 250), OP_EQ,
            FREE_CAPACITY_OK);
  tt_u64_op(conn[0].admissions.credit_milli, OP_EQ, 0);
 done:
  for (unsigned i = 0; i < 34; ++i)
    free_capacity_release(&circ[i]);
}

static void
test_free_capacity_live_bound(void *arg)
{
  free_capacity_t owner;
  free_capacity_conn_t *conn = NULL;
  free_capacity_circuit_t *circ = NULL;
  (void)arg;
  free_capacity_init(&owner, 0);
  conn = tor_calloc(FREE_CAPACITY_MAX_CIRCUITS + 1, sizeof(*conn));
  circ = tor_calloc(FREE_CAPACITY_MAX_CIRCUITS + 1, sizeof(*circ));
  for (unsigned i = 0; i <= FREE_CAPACITY_MAX_CIRCUITS; ++i) {
    uint64_t now = (uint64_t)i * 63;
    tt_int_op(free_capacity_conn_init(&conn[i], &owner, now), OP_EQ,
              FREE_CAPACITY_OK);
    tt_int_op(free_capacity_admit(&conn[i], &circ[i], now), OP_EQ,
              i == FREE_CAPACITY_MAX_CIRCUITS ? FREE_CAPACITY_REFUSE :
              FREE_CAPACITY_OK);
  }
  tt_uint_op(owner.live_circuits, OP_EQ, FREE_CAPACITY_MAX_CIRCUITS);
  free_capacity_release(&circ[0]);
  free_capacity_release(&circ[0]);
  tt_uint_op(owner.live_circuits, OP_EQ, FREE_CAPACITY_MAX_CIRCUITS - 1);
  tt_int_op(free_capacity_admit(&conn[FREE_CAPACITY_MAX_CIRCUITS],
                              &circ[FREE_CAPACITY_MAX_CIRCUITS],
                              FREE_CAPACITY_MAX_CIRCUITS * 63), OP_EQ,
            FREE_CAPACITY_OK);
 done:
  if (circ)
    for (unsigned i = 0; i <= FREE_CAPACITY_MAX_CIRCUITS; ++i)
      free_capacity_release(&circ[i]);
  tor_free(conn);
  tor_free(circ);
}

static void
test_free_capacity_queue(void *arg)
{
  free_capacity_t owner, foreign_owner;
  free_capacity_conn_t conn;
  free_capacity_circuit_t circ[8] = {{0}};
  free_capacity_queue_ticket_t tickets[33] = {{0}};
  free_capacity_queue_ticket_t previous, next, later, stale, fresh, foreign;
  (void)arg;
  free_capacity_init(&owner, 0);
  free_capacity_init(&foreign_owner, 0);
  tt_int_op(free_capacity_conn_init(&conn, &owner, 0), OP_EQ,
            FREE_CAPACITY_OK);
  for (unsigned i = 0; i < 8; ++i)
    tt_int_op(free_capacity_admit(&conn, &circ[i], 0), OP_EQ,
              FREE_CAPACITY_OK);
  for (unsigned i = 0; i < 32; ++i)
    tt_int_op(free_capacity_queue_push(&circ[0], 2053, 0, &tickets[i]), OP_EQ,
              FREE_CAPACITY_OK);
  tt_uint_op(owner.queued_bytes, OP_EQ, 32 * 2053);
  tt_int_op(free_capacity_queue_push(&circ[0], 2053, 0, &tickets[32]), OP_EQ,
            FREE_CAPACITY_CLOSE);
  tt_u64_op(tickets[32].serial, OP_EQ, 0);
  tt_uint_op(circ[0].queue_count, OP_EQ, 32);
  tt_int_op(free_capacity_queue_remove(&circ[0], &tickets[0], 0), OP_EQ,
            FREE_CAPACITY_CLOSE);
  free_capacity_release(&circ[0]);
  tt_uint_op(owner.queued_bytes, OP_EQ, 0);
  /* Two independent Tor queues can flush in either order, releasing exactly
   * that cell's allocation cost and preserving the oldest surviving time. */
  tt_int_op(free_capacity_queue_push(&circ[1], 2053, 0, &previous), OP_EQ,
            FREE_CAPACITY_OK);
  tt_int_op(free_capacity_queue_push(&circ[1], 4096, 1, &next), OP_EQ,
            FREE_CAPACITY_OK);
  tt_int_op(free_capacity_queue_push(&circ[1], 2054, 2, &later), OP_EQ,
            FREE_CAPACITY_OK);
  tt_int_op(free_capacity_queue_remove(&circ[1], &next, 3), OP_EQ,
            FREE_CAPACITY_OK);
  tt_uint_op(owner.queued_bytes, OP_EQ, 4107);
  tt_uint_op(circ[1].queue_count, OP_EQ, 2);
  tt_int_op(free_capacity_queue_remove(&circ[1], &next, 4), OP_EQ,
            FREE_CAPACITY_BAD_STATE);
  tt_uint_op(owner.queued_bytes, OP_EQ, 4107);
  tt_int_op(free_capacity_check(&circ[1], 4999), OP_EQ, FREE_CAPACITY_OK);
  tt_int_op(free_capacity_queue_remove(&circ[1], &previous, 4999), OP_EQ,
            FREE_CAPACITY_OK);
  tt_uint_op(owner.queued_bytes, OP_EQ, 2054);
  tt_int_op(free_capacity_check(&circ[1], 5001), OP_EQ, FREE_CAPACITY_OK);
  tt_int_op(free_capacity_check(&circ[1], 5002), OP_EQ, FREE_CAPACITY_CLOSE);
  free_capacity_release(&circ[1]);
  tt_uint_op(owner.queued_bytes, OP_EQ, 0);
  tt_int_op(free_capacity_queue_push(&circ[2], UINT32_MAX, 5002, &fresh), OP_EQ,
            FREE_CAPACITY_CLOSE);
  tt_uint_op(owner.queued_bytes, OP_EQ, 0);
  tt_int_op(free_capacity_queue_push(&circ[3], FREE_CAPACITY_QUEUE_BYTES,
                                   5002, &fresh), OP_EQ, FREE_CAPACITY_OK);
  tt_int_op(free_capacity_queue_push(&circ[4], 1, 5002, &stale), OP_EQ,
            FREE_CAPACITY_CLOSE);
  tt_uint_op(circ[4].queue_count, OP_EQ, 0);
  tt_int_op(free_capacity_queue_remove(&circ[3], &fresh, 5002), OP_EQ,
            FREE_CAPACITY_OK);
  tt_uint_op(owner.queued_bytes, OP_EQ, 0);
  tt_int_op(free_capacity_queue_push(&circ[5], 2053, 5002, &stale), OP_EQ,
            FREE_CAPACITY_OK);
  free_capacity_release(&circ[5]);
  tt_int_op(free_capacity_admit(&conn, &circ[5], 5002), OP_EQ,
            FREE_CAPACITY_OK);
  tt_int_op(free_capacity_queue_push(&circ[5], 4096, 5002, &fresh), OP_EQ,
            FREE_CAPACITY_OK);
  tt_int_op(free_capacity_queue_remove(&circ[5], &stale, 100000), OP_EQ,
            FREE_CAPACITY_BAD_STATE);
  tt_u64_op(owner.last_ms, OP_EQ, 5002);
  tt_uint_op(owner.queued_bytes, OP_EQ, 4096);
  foreign = fresh;
  foreign.owner = &foreign_owner;
  tt_int_op(free_capacity_queue_remove(&circ[5], &foreign, 5002), OP_EQ,
            FREE_CAPACITY_BAD_STATE);
  tt_int_op(free_capacity_queue_remove(&circ[5], &fresh, 5002), OP_EQ,
            FREE_CAPACITY_OK);
  tt_uint_op(owner.queued_bytes, OP_EQ, 0);
 done:
  for (unsigned i = 0; i < 8; ++i)
    free_capacity_release(&circ[i]);
}

static void
test_free_capacity_queue_ticket_exhaustion(void *arg)
{
  free_capacity_t owner;
  free_capacity_conn_t conn;
  free_capacity_circuit_t circ = {0};
  free_capacity_queue_ticket_t ticket;
  (void)arg;
  free_capacity_init(&owner, 0);
  tt_int_op(free_capacity_conn_init(&conn, &owner, 0), OP_EQ,
            FREE_CAPACITY_OK);
  tt_int_op(free_capacity_admit(&conn, &circ, 0), OP_EQ, FREE_CAPACITY_OK);
  owner.last_queue_ticket = UINT64_MAX - 1;
  tt_int_op(free_capacity_queue_push(&circ, 2053, 0, &ticket), OP_EQ,
            FREE_CAPACITY_OK);
  tt_u64_op(ticket.serial, OP_EQ, UINT64_MAX);
  tt_int_op(free_capacity_queue_remove(&circ, &ticket, 0), OP_EQ,
            FREE_CAPACITY_OK);
  tt_int_op(free_capacity_queue_push(&circ, 2053, 0, &ticket), OP_EQ,
            FREE_CAPACITY_CLOSE);
  tt_u64_op(ticket.serial, OP_EQ, 0);
  tt_uint_op(owner.queued_bytes, OP_EQ, 0);
  tt_uint_op(circ.queue_count, OP_EQ, 0);
 done:
  free_capacity_release(&circ);
}

static void
test_free_capacity_clock_and_age(void *arg)
{
  free_capacity_t owner;
  free_capacity_conn_t conn, other;
  free_capacity_circuit_t circ = {0};
  uint64_t credit;
  (void)arg;
  free_capacity_init(&owner, 10);
  tt_int_op(free_capacity_conn_init(&conn, &owner, 10), OP_EQ,
            FREE_CAPACITY_OK);
  tt_int_op(free_capacity_admit(&conn, &circ, 10), OP_EQ, FREE_CAPACITY_OK);
  tt_int_op(free_capacity_send(&circ, &conn, 128, 2053, 10), OP_EQ,
            FREE_CAPACITY_OK);
  tt_int_op(free_capacity_check(&circ, 110), OP_EQ, FREE_CAPACITY_OK);
  credit = circ.cells.credit_milli;
  tt_int_op(free_capacity_send(&circ, &conn, 0, 1, 109), OP_EQ,
            FREE_CAPACITY_CLOCK_ERROR);
  tt_u64_op(circ.cells.credit_milli, OP_EQ, credit);
  tt_int_op(free_capacity_conn_init(&other, &owner, 109), OP_EQ,
            FREE_CAPACITY_CLOCK_ERROR);
  tt_int_op(free_capacity_check(&circ, 600009), OP_EQ, FREE_CAPACITY_OK);
  tt_int_op(free_capacity_check(&circ, 600010), OP_EQ, FREE_CAPACITY_CLOSE);
  tt_int_op(free_capacity_receive(&circ, &conn, 1, 2053, 600010), OP_EQ,
            FREE_CAPACITY_CLOSE);
  tt_u64_op(owner.received_bytes, OP_EQ, 2053);
  free_capacity_release(&circ);
  /* UINT64_MAX jumps saturate before multiply; relative expiry also works
   * near the maximum timestamp without adding lifetime to admission time. */
  tt_int_op(free_capacity_link_send(&conn, FREE_CAPACITY_CONN_BYTE_BURST,
                                  UINT64_MAX - 100), OP_EQ, FREE_CAPACITY_OK);
  tt_int_op(free_capacity_admit(&conn, &circ, UINT64_MAX - 100), OP_EQ,
            FREE_CAPACITY_OK);
  tt_int_op(free_capacity_check(&circ, UINT64_MAX), OP_EQ, FREE_CAPACITY_OK);
  tt_int_op(free_capacity_check(&circ, 0), OP_EQ, FREE_CAPACITY_CLOCK_ERROR);
 done:
  free_capacity_release(&circ);
}

static void
test_free_capacity_two_links(void *arg)
{
  free_capacity_t owner, foreign_owner;
  free_capacity_conn_t previous, next, foreign;
  free_capacity_circuit_t circ = {0};
  uint64_t global_credit, cell_credit;
  (void)arg;
  free_capacity_init(&owner, 0);
  free_capacity_init(&foreign_owner, 0);
  tt_int_op(free_capacity_conn_init(&previous, &owner, 0), OP_EQ,
            FREE_CAPACITY_OK);
  tt_int_op(free_capacity_conn_init(&next, &owner, 0), OP_EQ,
            FREE_CAPACITY_OK);
  tt_int_op(free_capacity_conn_init(&foreign, &foreign_owner, 0), OP_EQ,
            FREE_CAPACITY_OK);
  tt_int_op(free_capacity_admit(&previous, &circ, 0), OP_EQ,
            FREE_CAPACITY_OK);
  tt_int_op(free_capacity_receive(&circ, &previous, 1, 2053, 0), OP_EQ,
            FREE_CAPACITY_OK);
  tt_int_op(free_capacity_send(&circ, &next, 1, 2053, 0), OP_EQ,
            FREE_CAPACITY_OK);
  tt_u64_op(circ.cells.credit_milli, OP_EQ, 126000);
  tt_u64_op(previous.bytes.credit_milli, OP_EQ,
            ((uint64_t)FREE_CAPACITY_CONN_BYTE_BURST - 2053) * 1000);
  tt_u64_op(next.bytes.credit_milli, OP_EQ,
            ((uint64_t)FREE_CAPACITY_CONN_BYTE_BURST - 2053) * 1000);
  tt_u64_op(owner.bytes.credit_milli, OP_EQ,
            ((uint64_t)FREE_CAPACITY_BYTE_BURST - 4106) * 1000);
  /* Outbound on one exhausted link cannot consume the other link's credit. */
  tt_int_op(free_capacity_link_send(&next,
                    FREE_CAPACITY_CONN_BYTE_BURST - 2053, 0), OP_EQ,
            FREE_CAPACITY_OK);
  cell_credit = circ.cells.credit_milli;
  tt_int_op(free_capacity_send(&circ, &next, 1, 2053, 0), OP_EQ,
            FREE_CAPACITY_WAIT);
  tt_u64_op(circ.cells.credit_milli, OP_EQ, cell_credit);
  tt_int_op(free_capacity_send(&circ, &previous, 1, 2053, 0), OP_EQ,
            FREE_CAPACITY_OK);
  global_credit = owner.bytes.credit_milli;
  cell_credit = circ.cells.credit_milli;
  tt_int_op(free_capacity_send(&circ, &foreign, 1, 2053, 1000), OP_EQ,
            FREE_CAPACITY_BAD_STATE);
  tt_int_op(free_capacity_receive(&circ, &foreign, 1, 2053, 1000), OP_EQ,
            FREE_CAPACITY_BAD_STATE);
  tt_u64_op(owner.last_ms, OP_EQ, 0);
  tt_u64_op(owner.bytes.credit_milli, OP_EQ, global_credit);
  tt_u64_op(circ.cells.credit_milli, OP_EQ, cell_credit);
  tt_u64_op(foreign_owner.received_bytes, OP_EQ, 0);
 done:
  free_capacity_release(&circ);
}

static void
test_free_capacity_paid_hold(void *arg)
{
  free_capacity_t owner;
  free_capacity_conn_t conn;
  free_capacity_circuit_t circ = {0};
  free_capacity_queue_ticket_t ticket, rejected;
  uint64_t credit;
  (void)arg;
  free_capacity_init(&owner, 0);
  tt_int_op(free_capacity_conn_init(&conn, &owner, 0), OP_EQ, FREE_CAPACITY_OK);
  tt_int_op(free_capacity_admit(&conn, &circ, 0), OP_EQ, FREE_CAPACITY_OK);
  tt_int_op(free_capacity_send(&circ, &conn, 128, 2053, 0), OP_EQ,
            FREE_CAPACITY_OK);
  credit = circ.cells.credit_milli;
  tt_int_op(free_capacity_queue_hold(&circ, 2053, 600001, 600001, &ticket),
            OP_EQ, FREE_CAPACITY_OK);
  tt_u64_op(circ.cells.credit_milli, OP_EQ, credit);
  tt_uint_op(owner.queued_bytes, OP_EQ, 2053);
  tt_int_op(free_capacity_queue_hold(&circ, 2053, 600003, 600002, &rejected),
            OP_EQ, FREE_CAPACITY_CLOCK_ERROR);
  tt_u64_op(owner.last_ms, OP_EQ, 600001);
  tt_int_op(free_capacity_queue_hold(&circ, 2053, 600001, 605001, &rejected),
            OP_EQ, FREE_CAPACITY_CLOSE);
  tt_u64_op(rejected.serial, OP_EQ, 0);
  tt_int_op(free_capacity_queue_discard(&circ, &ticket), OP_EQ,
            FREE_CAPACITY_OK);
  tt_uint_op(owner.queued_bytes, OP_EQ, 0);
  tt_u64_op(circ.cells.credit_milli, OP_EQ, credit);
 done:
  free_capacity_release(&circ);
}

#define FREE_TEST(name) { #name, test_free_capacity_##name, 0, NULL, NULL }
struct testcase_t free_capacity_tests[] = {
  FREE_TEST(refill),
  FREE_TEST(atomic_and_received),
  FREE_TEST(aggregate),
  FREE_TEST(admission),
  FREE_TEST(live_bound),
  FREE_TEST(queue),
  FREE_TEST(queue_ticket_exhaustion),
  FREE_TEST(clock_and_age),
  FREE_TEST(two_links),
  FREE_TEST(paid_hold),
  END_OF_TESTCASES
};
