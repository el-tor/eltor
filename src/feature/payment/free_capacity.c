/* Copyright (c) 2026, The El Tor Project. */
/* See LICENSE for licensing information. */
#include "orconfig.h"
#include "feature/payment/free_capacity.h"
#include <string.h>

static void
bucket_init(free_capacity_bucket_t *b, uint32_t rate, uint32_t burst,
            uint64_t now_ms)
{
  b->rate = rate;
  b->burst = burst;
  b->last_ms = now_ms;
  b->credit_milli = (uint64_t)burst * 1000;
}

/* One millisecond adds rate milli-units. Test the saturation threshold before
 * multiplication, including for UINT64_MAX elapsed time. No fractional credit
 * is lost between calls and a full bucket does not bank future refill. */
static void
bucket_refill(free_capacity_bucket_t *b, uint64_t now_ms)
{
  uint64_t elapsed = now_ms - b->last_ms;
  uint64_t gap = (uint64_t)b->burst * 1000 - b->credit_milli;
  if (elapsed > gap / b->rate)
    b->credit_milli = (uint64_t)b->burst * 1000;
  else
    b->credit_milli += elapsed * b->rate;
  b->last_ms = now_ms;
}

static bool
bucket_fits(const free_capacity_bucket_t *b, uint64_t cost)
{
  return cost <= b->credit_milli / 1000;
}

static void
bucket_charge(free_capacity_bucket_t *b, uint64_t cost)
{
  /* Oversized received traffic consumes all remaining credit without integer
   * overflow. An outbound debit reaches this only after every fits check. */
  if (!bucket_fits(b, cost))
    b->credit_milli = 0;
  else
    b->credit_milli -= cost * 1000;
}

static void
counter_add(uint64_t *counter, uint64_t n)
{
  *counter = n > UINT64_MAX - *counter ? UINT64_MAX : *counter + n;
}

static free_capacity_result_t
advance_owner(free_capacity_t *owner, uint64_t now_ms)
{
  if (!owner)
    return FREE_CAPACITY_BAD_STATE;
  if (now_ms < owner->last_ms)
    return FREE_CAPACITY_CLOCK_ERROR;
  owner->last_ms = now_ms;
  bucket_refill(&owner->admissions, now_ms);
  bucket_refill(&owner->bytes, now_ms);
  return FREE_CAPACITY_OK;
}

static free_capacity_result_t
advance(free_capacity_conn_t *conn, uint64_t now_ms)
{
  free_capacity_result_t r;
  if (!conn)
    return FREE_CAPACITY_BAD_STATE;
  r = advance_owner(conn->owner, now_ms);
  if (r != FREE_CAPACITY_OK)
    return r;
  bucket_refill(&conn->admissions, now_ms);
  bucket_refill(&conn->bytes, now_ms);
  return FREE_CAPACITY_OK;
}

void
free_capacity_init(free_capacity_t *owner, uint64_t now_ms)
{
  memset(owner, 0, sizeof(*owner));
  owner->last_ms = now_ms;
  bucket_init(&owner->admissions, FREE_CAPACITY_ADMISSION_RATE,
              FREE_CAPACITY_ADMISSION_BURST, now_ms);
  bucket_init(&owner->bytes, FREE_CAPACITY_BYTE_RATE,
              FREE_CAPACITY_BYTE_BURST, now_ms);
}

free_capacity_result_t
free_capacity_conn_init(free_capacity_conn_t *conn, free_capacity_t *owner,
                        uint64_t now_ms)
{
  if (!conn || !owner)
    return FREE_CAPACITY_BAD_STATE;
  if (now_ms < owner->last_ms)
    return FREE_CAPACITY_CLOCK_ERROR;
  memset(conn, 0, sizeof(*conn));
  conn->owner = owner;
  bucket_init(&conn->admissions, FREE_CAPACITY_CONN_ADMISSION_RATE,
              FREE_CAPACITY_CONN_ADMISSION_BURST, now_ms);
  bucket_init(&conn->bytes, FREE_CAPACITY_CONN_BYTE_RATE,
              FREE_CAPACITY_CONN_BYTE_BURST, now_ms);
  return advance(conn, now_ms);
}

free_capacity_result_t
free_capacity_admit(free_capacity_conn_t *conn,
                    free_capacity_circuit_t *circ, uint64_t now_ms)
{
  free_capacity_result_t r;
  if (!circ || circ->active)
    return FREE_CAPACITY_BAD_STATE;
  r = advance(conn, now_ms);
  if (r != FREE_CAPACITY_OK)
    return r;
  if (conn->owner->live_circuits >= FREE_CAPACITY_MAX_CIRCUITS ||
      !bucket_fits(&conn->owner->admissions, 1) ||
      !bucket_fits(&conn->admissions, 1))
    return FREE_CAPACITY_REFUSE;
  bucket_charge(&conn->owner->admissions, 1);
  bucket_charge(&conn->admissions, 1);
  memset(circ, 0, sizeof(*circ));
  circ->active = true;
  circ->owner = conn->owner;
  circ->admitted_ms = now_ms;
  bucket_init(&circ->cells, FREE_CAPACITY_CELL_RATE,
              FREE_CAPACITY_CELL_BURST, now_ms);
  ++conn->owner->live_circuits;
  return FREE_CAPACITY_OK;
}

free_capacity_result_t
free_capacity_check(free_capacity_circuit_t *circ, uint64_t now_ms)
{
  free_capacity_result_t r;
  if (!circ || !circ->active)
    return FREE_CAPACITY_BAD_STATE;
  r = advance_owner(circ->owner, now_ms);
  if (r != FREE_CAPACITY_OK)
    return r;
  if (circ->closing ||
      now_ms - circ->admitted_ms >= FREE_CAPACITY_LIFETIME_MS ||
      (circ->queue_count &&
       now_ms - circ->queue_time[circ->queue_head] >=
       FREE_CAPACITY_QUEUE_AGE_MS)) {
    circ->closing = true;
    return FREE_CAPACITY_CLOSE;
  }
  bucket_refill(&circ->cells, now_ms);
  return FREE_CAPACITY_OK;
}

static free_capacity_result_t
link_charge(free_capacity_conn_t *conn, uint64_t bytes, uint64_t now_ms,
            bool received)
{
  free_capacity_result_t r = advance(conn, now_ms);
  bool fits;
  if (r != FREE_CAPACITY_OK)
    return r;
  fits = bucket_fits(&conn->owner->bytes, bytes) &&
         bucket_fits(&conn->bytes, bytes);
  if (!fits && !received)
    return FREE_CAPACITY_WAIT;
  bucket_charge(&conn->owner->bytes, bytes);
  bucket_charge(&conn->bytes, bytes);
  counter_add(received ? &conn->owner->received_bytes :
                        &conn->owner->sent_bytes, bytes);
  return fits ? FREE_CAPACITY_OK : FREE_CAPACITY_CLOSE;
}

free_capacity_result_t
free_capacity_link_receive(free_capacity_conn_t *conn, uint64_t bytes,
                           uint64_t now_ms)
{
  return link_charge(conn, bytes, now_ms, true);
}

free_capacity_result_t
free_capacity_link_send(free_capacity_conn_t *conn, uint64_t bytes,
                        uint64_t now_ms)
{
  return link_charge(conn, bytes, now_ms, false);
}

static free_capacity_result_t
circuit_charge(free_capacity_circuit_t *circ, free_capacity_conn_t *conn,
               uint64_t cells, uint64_t bytes, uint64_t now_ms, bool received)
{
  free_capacity_result_t r;
  bool fits;
  if (!circ || !conn || !conn->owner || circ->owner != conn->owner)
    return FREE_CAPACITY_BAD_STATE;
  r = free_capacity_check(circ, now_ms);
  /* An expired live circuit still consumed received link bandwidth. Do not
   * grant cell work, but retain physical-byte accounting before closing. */
  if (r != FREE_CAPACITY_OK) {
    if (r == FREE_CAPACITY_CLOSE && received)
      (void)link_charge(conn, bytes, now_ms, true);
    return r;
  }
  r = advance(conn, now_ms);
  if (r != FREE_CAPACITY_OK)
    return r;
  fits = bucket_fits(&circ->cells, cells) &&
         bucket_fits(&conn->bytes, bytes) &&
         bucket_fits(&conn->owner->bytes, bytes);
  if (!fits && !received)
    return FREE_CAPACITY_WAIT;
  bucket_charge(&circ->cells, cells);
  (void)link_charge(conn, bytes, now_ms, received);
  if (!fits)
    circ->closing = true;
  return fits ? FREE_CAPACITY_OK : FREE_CAPACITY_CLOSE;
}

free_capacity_result_t
free_capacity_receive(free_capacity_circuit_t *circ, free_capacity_conn_t *conn,
                       uint64_t cells, uint64_t bytes, uint64_t now_ms)
{
  return circuit_charge(circ, conn, cells, bytes, now_ms, true);
}

free_capacity_result_t
free_capacity_send(free_capacity_circuit_t *circ, free_capacity_conn_t *conn,
                    uint64_t cells, uint64_t bytes, uint64_t now_ms)
{
  return circuit_charge(circ, conn, cells, bytes, now_ms, false);
}

free_capacity_result_t
free_capacity_queue_push(free_capacity_circuit_t *circ, uint32_t bytes,
                         uint64_t now_ms)
{
  free_capacity_result_t r = free_capacity_check(circ, now_ms);
  free_capacity_t *owner;
  unsigned index;
  if (r != FREE_CAPACITY_OK)
    return r;
  if (!bytes)
    return FREE_CAPACITY_BAD_STATE;
  owner = circ->owner;
  if (circ->queue_count == FREE_CAPACITY_QUEUE_CELLS ||
      bytes > FREE_CAPACITY_QUEUE_BYTES - owner->queued_bytes) {
    circ->closing = true;
    return FREE_CAPACITY_CLOSE;
  }
  index = (circ->queue_head + circ->queue_count) % FREE_CAPACITY_QUEUE_CELLS;
  circ->queue_time[index] = now_ms;
  circ->queue_size[index] = bytes;
  ++circ->queue_count;
  circ->queued_bytes += bytes;
  owner->queued_bytes += bytes;
  return FREE_CAPACITY_OK;
}

free_capacity_result_t
free_capacity_queue_pop(free_capacity_circuit_t *circ, uint64_t now_ms)
{
  free_capacity_result_t r = free_capacity_check(circ, now_ms);
  uint32_t bytes;
  if (r != FREE_CAPACITY_OK)
    return r;
  if (!circ->queue_count)
    return FREE_CAPACITY_BAD_STATE;
  bytes = circ->queue_size[circ->queue_head];
  circ->owner->queued_bytes -= bytes;
  circ->queued_bytes -= bytes;
  circ->queue_size[circ->queue_head] = 0;
  circ->queue_head = (circ->queue_head + 1) % FREE_CAPACITY_QUEUE_CELLS;
  --circ->queue_count;
  return FREE_CAPACITY_OK;
}

void
free_capacity_release(free_capacity_circuit_t *circ)
{
  if (circ && circ->active) {
    free_capacity_t *owner = circ->owner;
    owner->queued_bytes -= circ->queued_bytes;
    --owner->live_circuits;
    memset(circ, 0, sizeof(*circ));
  }
}
