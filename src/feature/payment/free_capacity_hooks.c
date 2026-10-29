/* Copyright (c) 2026, The El Tor Project. */
/* See LICENSE for licensing information. */
#include "orconfig.h"
#define CHANNEL_OBJECT_PRIVATE
#include "core/or/or.h"
#include "feature/payment/free_capacity_hooks.h"
#include "feature/payment/payment_resources.h"
#include "feature/payment/payment_circuit.h"
#include "feature/payment/payment_origin.h"
#include "core/or/circuit_st.h"
#include "core/or/or_circuit_st.h"
#include "core/or/origin_circuit_st.h"
#include "core/or/cell_queue_st.h"
#include "core/or/or_connection_st.h"
#include "core/or/channel.h"
#include "core/or/channeltls.h"
#include "core/or/circuitlist.h"
#include "core/or/circuitmux.h"
#include "core/or/relay.h"
#include "core/or/scheduler.h"
#include "core/mainloop/connection.h"
#include "lib/evloop/timers.h"
#include "lib/time/compat_time.h"

typedef struct free_capacity_context_t {
  free_capacity_circuit_t limit;
  protocol_budget_memory_t memory;
  circuit_t *circ;
  or_connection_t *setup_link;
  struct free_capacity_context_t *next, **previous;
  bool waiting, data_only, paid, confirmed, first_link, setup_received;
  uint64_t wake_ms;
} free_capacity_context_t;

typedef struct free_capacity_link_t {
  free_capacity_conn_t limit;
  protocol_budget_memory_t memory;
} free_capacity_link_t;

static free_capacity_context_t *contexts;
static tor_timer_t *wake_timer;
static protocol_budget_memory_t timer_memory;
static uint64_t scheduled_ms = UINT64_MAX;
static void request_wakeup(uint64_t);
static void schedule_wakeup(void);

static uint64_t
deadline_after(uint64_t start, uint64_t interval)
{
  return start > UINT64_MAX - interval ? UINT64_MAX : start + interval;
}

static free_capacity_link_t *
link_get(or_connection_t *conn)
{
  protocol_budget_memory_t memory = {0};
  free_capacity_link_t *link;
  if (!conn || conn->base_.marked_for_close)
    return NULL;
  if (conn->free_capacity)
    return conn->free_capacity;
  if (payment_resources_reserve(&memory, sizeof(*link)) != PROTOCOL_BUDGET_OK)
    return NULL;
  link = tor_malloc_zero(sizeof(*link));
  link->memory = memory;
  free_capacity_t *owner = payment_resources_free();
  if (free_capacity_conn_init(&link->limit, owner, monotime_absolute_msec()) !=
      FREE_CAPACITY_OK) {
    tor_free(link);
    (void)payment_resources_release(&memory);
    return NULL;
  }
  conn->free_capacity = link;
  return link;
}

void
free_capacity_connection_free(or_connection_t *conn)
{
  if (conn && conn->free_capacity) {
    protocol_budget_memory_t memory = conn->free_capacity->memory;
    tor_free(conn->free_capacity);
    (void)payment_resources_release(&memory);
  }
}

MOCK_IMPL(bool,
free_capacity_paid_data_active, (const circuit_t *circ))
{
  if (!circ || circ->marked_for_close || !circ->free_capacity ||
      !circ->free_capacity->paid)
    return false;
  if (CIRCUIT_IS_ORIGIN(circ))
    return payment_origin_data_active(CONST_TO_ORIGIN_CIRCUIT(circ),
                                       monotime_absolute_msec());
  return payment_circuit_data_active(CONST_TO_OR_CIRCUIT(circ),
                                      monotime_absolute_msec());
}

static bool
head_is_payment_control(cell_queue_t *queue)
{
  packed_cell_t *head = TOR_SIMPLEQ_FIRST(&queue->head);
  return head && head->payment_control;
}

static bool
adopt_held_queue(circuit_t *circ, cell_queue_t *queue)
{
  packed_cell_t *cell;
  TOR_SIMPLEQ_FOREACH(cell, &queue->head, next) {
    if (cell->free_capacity_ticket.serial) continue;
    if (free_capacity_queue_hold(&circ->free_capacity->limit,
        packed_cell_mem_cost(), cell->free_queue_inserted_ms,
        monotime_absolute_msec(), &cell->free_capacity_ticket) !=
        FREE_CAPACITY_OK)
      return false;
    cell->free_capacity_circuit = circ;
  }
  return true;
}

static bool
adopt_held_queues(circuit_t *circ)
{
  if (!adopt_held_queue(circ, &circ->n_chan_cells)) return false;
  return CIRCUIT_IS_ORIGIN(circ) ||
    adopt_held_queue(circ, &TO_OR_CIRCUIT(circ)->p_chan_cells);
}

static void
set_queue_activity(free_capacity_context_t *context, bool active)
{
  circuit_t *circ = context->circ;
  channel_t *chan = circ->n_chan;
  if (chan && chan->cmux &&
      circuitmux_is_circuit_attached(chan->cmux, circ)) {
    bool runnable = active || (context->data_only &&
        head_is_payment_control(&circ->n_chan_cells));
    circuitmux_set_num_cells(chan->cmux, circ,
                            runnable ? circ->n_chan_cells.n : 0);
    if (runnable && circ->n_chan_cells.n)
      scheduler_channel_has_waiting_cells(chan);
  }
  if (!CIRCUIT_IS_ORIGIN(circ)) {
    or_circuit_t *orcirc = TO_OR_CIRCUIT(circ);
    chan = orcirc->p_chan;
    if (chan && chan->cmux &&
        circuitmux_is_circuit_attached(chan->cmux, circ)) {
      bool runnable = active || (context->data_only &&
          head_is_payment_control(&orcirc->p_chan_cells));
      circuitmux_set_num_cells(chan->cmux, circ,
                              runnable ? orcirc->p_chan_cells.n : 0);
      if (runnable && orcirc->p_chan_cells.n)
        scheduler_channel_has_waiting_cells(chan);
    }
  }
}

static bool
held_queue_expired(const free_capacity_context_t *context, uint64_t now_ms)
{
  if (!context->limit.queue_count) return false;
  for (unsigned i = 0; i < FREE_CAPACITY_QUEUE_CELLS; ++i)
    if (context->limit.queue_ticket[i] &&
        (now_ms < context->limit.queue_time[i] ||
         now_ms - context->limit.queue_time[i] >= FREE_CAPACITY_QUEUE_AGE_MS))
      return true;
  return false;
}

static void
wake_callback(tor_timer_t *timer, void *arg, const monotime_t *now)
{
  uint64_t now_ms = monotime_absolute_msec();
  scheduled_ms = UINT64_MAX;
  (void)timer; (void)arg; (void)now;
  /* One bounded list (<=4096); never an allocation per waiting cell. */
  for (free_capacity_context_t *c = contexts; c; c = c->next) {
    if (c->circ->marked_for_close)
      continue;
    if (held_queue_expired(c, now_ms) || (!c->paid &&
        free_capacity_check(&c->limit, now_ms) != FREE_CAPACITY_OK)) {
      circuit_mark_for_close(c->circ, END_CIRC_REASON_RESOURCELIMIT);
    } else if (c->waiting && now_ms >= c->wake_ms) {
      c->waiting = false;
      set_queue_activity(c, true);
    }
  }
  schedule_wakeup();
}

static void
schedule_wakeup(void)
{
  uint64_t earliest = UINT64_MAX;
  for (free_capacity_context_t *c = contexts; c; c = c->next) {
    uint64_t due;
    if (c->circ->marked_for_close)
      continue;
    due = c->paid ? UINT64_MAX :
      c->limit.admitted_ms + FREE_CAPACITY_LIFETIME_MS;
    if (c->waiting && c->wake_ms < due)
      due = c->wake_ms;
    for (unsigned i = 0; i < FREE_CAPACITY_QUEUE_CELLS; ++i) {
      if (c->limit.queue_ticket[i] &&
          deadline_after(c->limit.queue_time[i], FREE_CAPACITY_QUEUE_AGE_MS) < due)
        due = deadline_after(c->limit.queue_time[i], FREE_CAPACITY_QUEUE_AGE_MS);
    }
    if (due < earliest)
      earliest = due;
  }
  if (earliest == UINT64_MAX) {
    if (wake_timer) timer_disable(wake_timer);
    return;
  }
  request_wakeup(earliest);
}

/* Constant work on the cell fast path. An obsolete early wake after a queue
 * drains is harmless; only the bounded timer callback scans all contexts. */
static void
request_wakeup(uint64_t due)
{
  uint64_t now_ms = monotime_absolute_msec();
  struct timeval delay;
  if (due >= scheduled_ms) return;
  scheduled_ms = due;
  uint64_t ms = due > now_ms ? due - now_ms : 1;
  delay.tv_sec = ms / 1000;
  delay.tv_usec = (ms % 1000) * 1000;
  if (!wake_timer) wake_timer = timer_new(wake_callback, NULL);
  timer_schedule(wake_timer, &delay);
}

int
free_capacity_circuit_prepare(circuit_t *circ, or_connection_t *conn)
{
  protocol_budget_memory_t memory = {0};
  free_capacity_context_t temporary = {0}, *context;
  free_capacity_link_t *link;
  bool first_link = conn && !conn->free_capacity;
  uint64_t now_ms = monotime_absolute_msec();
  if (!circ || circ->free_capacity || circ->marked_for_close ||
      now_ms >= UINT64_MAX - FREE_CAPACITY_LIFETIME_MS)
    return -1;
  link = link_get(conn);
  if (first_link && !CIRCUIT_IS_ORIGIN(circ)) {
    /* This original CREATE arrived before any free circuit/link existed.
     * Existing enabled links were already charged by the serialized read hook.
     * Charge even when later context/admission allocation is refused. */
    free_capacity_conn_t temporary_link = {0};
    free_capacity_t *owner = payment_resources_free();
    now_ms = monotime_absolute_msec();
    free_capacity_conn_t *account = link ? &link->limit : &temporary_link;
    if (!link) (void)free_capacity_conn_init(account, owner, now_ms);
    if (free_capacity_link_receive(account,
          get_cell_network_size(conn->wide_circ_ids), now_ms) !=
        FREE_CAPACITY_OK)
      return -1;
    first_link = false;
  }
  if (!link) return -1;
  if (payment_resources_reserve(&memory, sizeof(*context)) != PROTOCOL_BUDGET_OK)
    return -1;
  if (!wake_timer && !timer_memory.active &&
      payment_resources_reserve(&timer_memory,
          timer_memory_cost() + sizeof(timer_memory)) != PROTOCOL_BUDGET_OK) {
    (void)payment_resources_release(&memory);
    return -1;
  }
  now_ms = monotime_absolute_msec();
  if (now_ms >= UINT64_MAX - FREE_CAPACITY_LIFETIME_MS ||
      free_capacity_admit(&link->limit, &temporary.limit, now_ms) !=
      FREE_CAPACITY_OK) {
    (void)payment_resources_release(&memory);
    if (!contexts) (void)payment_resources_release(&timer_memory);
    return -1;
  }
  context = tor_malloc_zero(sizeof(*context));
  context->limit = temporary.limit;
  context->memory = memory;
  context->circ = circ;
  context->setup_link = conn;
  context->first_link = first_link;
  context->next = contexts;
  context->previous = &contexts;
  if (contexts) contexts->previous = &context->next;
  contexts = context;
  circ->free_capacity = context;
  request_wakeup(now_ms + FREE_CAPACITY_LIFETIME_MS);
  return 0;
}

int
free_capacity_circuit_prepare_channel(circuit_t *circ, channel_t *chan)
{
  if (!chan || chan->magic != TLS_CHAN_MAGIC) return -1;
  return free_capacity_circuit_prepare(circ, BASE_CHAN_TO_TLS(chan)->conn);
}

int
free_capacity_circuit_setup_received(circuit_t *circ, channel_t *chan)
{
  if (!circ || CIRCUIT_IS_ORIGIN(circ) || !circ->free_capacity ||
      circ->marked_for_close || !chan ||
      chan->magic != TLS_CHAN_MAGIC)
    return -1;
  free_capacity_context_t *context = circ->free_capacity;
  if (context->setup_received) return 0;
  if (context->confirmed || BASE_CHAN_TO_TLS(chan)->conn != context->setup_link)
    return -1;
  free_capacity_link_t *link = link_get(BASE_CHAN_TO_TLS(chan)->conn);
  if (!link) return -1;
  context->setup_received = true;
  return free_capacity_receive(&context->limit, &link->limit, 1,
      context->first_link ? get_cell_network_size(chan->wide_circ_ids) : 0,
      monotime_absolute_msec()) == FREE_CAPACITY_OK ? 0 : -1;
}

int
free_capacity_circuit_confirm(circuit_t *circ)
{
  if (!circ || !circ->free_capacity || circ->marked_for_close ||
      free_capacity_check(&circ->free_capacity->limit,
                          monotime_absolute_msec()) != FREE_CAPACITY_OK)
    return -1;
  circ->free_capacity->confirmed = true;
  circ->free_capacity->setup_link = NULL;
  return 0;
}

int
free_capacity_circuit_admit(circuit_t *circ, or_connection_t *conn)
{
  if (free_capacity_circuit_prepare(circ, conn) < 0)
    return -1;
  if (free_capacity_circuit_confirm(circ) == 0)
    return 0;
  free_capacity_circuit_free(circ);
  return -1;
}

void
free_capacity_circuit_free(circuit_t *circ)
{
  free_capacity_context_t *context = circ->free_capacity;
  if (!context) return;
  /* All circuit queues must be cleared before context destruction. */
  tor_assert(!context->limit.queue_count);
  *context->previous = context->next;
  if (context->next) context->next->previous = context->previous;
  free_capacity_release(&context->limit);
  protocol_budget_memory_t memory = context->memory;
  tor_free(circ->free_capacity);
  (void)payment_resources_release(&memory);
  if (!contexts) {
    timer_free(wake_timer);
    (void)payment_resources_release(&timer_memory);
    scheduled_ms = UINT64_MAX;
  }
}

static bool
paid_wire_account(circuit_t *circ, uint32_t bytes)
{
  /* The origin cannot observe middle-hop physical charges; each relay owns
   * its authenticated accepted policy and aggregate two-link counter. */
  if (CIRCUIT_IS_ORIGIN(circ) ||
      payment_circuit_account_bytes(TO_OR_CIRCUIT(circ), bytes,
                                     monotime_absolute_msec())) return true;
  if (!circ->marked_for_close)
    circuit_mark_for_close(circ, END_CIRC_REASON_RESOURCELIMIT);
  return false;
}

static bool
setup_command(uint8_t command)
{
  return command == CELL_CREATE || command == CELL_CREATE2 ||
    command == CELL_CREATE_FAST || command == CELL_CREATED ||
    command == CELL_CREATED2 || command == CELL_CREATED_FAST ||
    command == CELL_DESTROY;
}

static bool
wire_account(or_connection_t *conn, circid_t circid, uint32_t bytes,
             bool fixed, uint8_t command, bool receive)
{
  circuit_t *circ = conn->chan ? circuit_get_by_circid_channel(circid,
                                      TLS_CHAN_TO_BASE(conn->chan)) : NULL;
  free_capacity_result_t result;
  if (circ && circ->free_capacity && circ->free_capacity->paid) {
    if (free_capacity_paid_data_active(circ))
      return paid_wire_account(circ, bytes);
    free_capacity_link_t *link = link_get(conn);
    bool unqueued_relay = !receive && fixed &&
      (command == CELL_RELAY || command == CELL_RELAY_EARLY);
    if (!link || unqueued_relay) {
      if (!circ->marked_for_close)
        circuit_mark_for_close(circ, END_CIRC_REASON_RESOURCELIMIT);
      return false;
    }
    result = receive ? free_capacity_link_receive(&link->limit, bytes,
                            monotime_absolute_msec()) :
      free_capacity_link_send(&link->limit, bytes, monotime_absolute_msec());
    if (result == FREE_CAPACITY_OK) return true;
    if (!circ->marked_for_close)
      circuit_mark_for_close(circ, END_CIRC_REASON_RESOURCELIMIT);
    return false;
  }
  if (circ && circ->free_capacity) {
    bool setup = fixed && setup_command(command);
    if (!circ->free_capacity->confirmed && !setup) {
      if (!circ->marked_for_close)
        circuit_mark_for_close(circ, END_CIRC_REASON_RESOURCELIMIT);
      return false;
    }
    free_capacity_link_t *link = link_get(conn);
    if (!link) {
      circuit_mark_for_close(circ, END_CIRC_REASON_RESOURCELIMIT);
      return false;
    }
    result = receive ? free_capacity_receive(&circ->free_capacity->limit,
        &link->limit, fixed ? 1 : 0, bytes, monotime_absolute_msec()) :
      free_capacity_send(&circ->free_capacity->limit, &link->limit,
        fixed ? 1 : 0, bytes, monotime_absolute_msec());
    if (result == FREE_CAPACITY_OK) return true;
    /* Direct writes have no bounded wait queue. Close on unavailable credit. */
    if (!circ->marked_for_close)
      circuit_mark_for_close(circ, END_CIRC_REASON_RESOURCELIMIT);
    return false;
  }
  if ((circ && !circ->free_capacity) || !conn->free_capacity)
    return true;
  result = receive ? free_capacity_link_receive(&conn->free_capacity->limit,
                 bytes, monotime_absolute_msec()) :
    free_capacity_link_send(&conn->free_capacity->limit, bytes,
                            monotime_absolute_msec());
  if (result == FREE_CAPACITY_OK) return true;
  if (!conn->base_.marked_for_close) connection_mark_for_close(TO_CONN(conn));
  return false;
}

bool
free_capacity_wire_receive(or_connection_t *conn, circid_t id, uint32_t bytes,
                           bool fixed, uint8_t command)
{ return wire_account(conn, id, bytes, fixed, command, true); }
bool
free_capacity_wire_send(or_connection_t *conn, circid_t id, uint32_t bytes,
                        bool fixed, uint8_t command)
{ return wire_account(conn, id, bytes, fixed, command, false); }

int
free_capacity_cell_reserve_command(circuit_t *circ,
    free_capacity_queue_ticket_t *ticket, uint8_t command)
{
  memset(ticket, 0, sizeof(*ticket));
  if (!circ || !circ->free_capacity) return 0;
  if (!circ->free_capacity->confirmed && !setup_command(command)) return -1;
  if (circ->free_capacity->paid) {
    if (free_capacity_paid_data_active(circ)) return 0;
    uint64_t now_ms = monotime_absolute_msec();
    return free_capacity_queue_hold(&circ->free_capacity->limit,
        packed_cell_mem_cost(), now_ms, now_ms, ticket) == FREE_CAPACITY_OK ?
        0 : -1;
  }
  return free_capacity_queue_push(&circ->free_capacity->limit,
      packed_cell_mem_cost(), monotime_absolute_msec(), ticket) ==
      FREE_CAPACITY_OK ? 0 : -1;
}

int
free_capacity_cell_reserve(circuit_t *circ, free_capacity_queue_ticket_t *ticket)
{
  return free_capacity_cell_reserve_command(circ, ticket, CELL_RELAY);
}

void
free_capacity_cell_release(circuit_t *circ, free_capacity_queue_ticket_t *ticket)
{
  if (!ticket->serial) return;
  tor_assert(circ && circ->free_capacity);
  tor_assert(free_capacity_queue_discard(&circ->free_capacity->limit,
                                         ticket) == FREE_CAPACITY_OK);
  memset(ticket, 0, sizeof(*ticket));
}

free_capacity_result_t
free_capacity_circuit_send_cell(circuit_t *circ, channel_t *chan,
                                 bool payment_control, uint8_t command)
{
  free_capacity_context_t *context = circ->free_capacity;
  free_capacity_link_t *link;
  or_connection_t *conn;
  free_capacity_result_t result;
  if (!context) return FREE_CAPACITY_OK;
  if (circ->marked_for_close) return FREE_CAPACITY_CLOSE;
  if (held_queue_expired(context, monotime_absolute_msec())) {
    context->data_only = false;
    circuit_mark_for_close(circ, END_CIRC_REASON_RESOURCELIMIT);
    set_queue_activity(context, false);
    return FREE_CAPACITY_CLOSE;
  }
  bool active_paid = context->paid && free_capacity_paid_data_active(circ);
  if (active_paid) {
    /* The packed-cell writer sees free_capacity_charged and must not debit
     * again. This is the existing last pre-pop accounting boundary. A failed
     * native write closes the circuit, so no credit is refunded/reused. */
    if (!paid_wire_account(circ, get_cell_network_size(chan->wide_circ_ids)))
      return FREE_CAPACITY_CLOSE;
    context->waiting = false;
    context->data_only = false;
    return FREE_CAPACITY_OK;
  }
  context->data_only = false;
  if ((!context->confirmed && !setup_command(command)) ||
      chan->magic != TLS_CHAN_MAGIC ||
      !(conn = BASE_CHAN_TO_TLS(chan)->conn) || !(link = link_get(conn))) {
    result = FREE_CAPACITY_CLOSE;
  } else if (context->paid && !adopt_held_queues(circ)) {
    result = FREE_CAPACITY_CLOSE;
  } else if (context->paid && !payment_control) {
    context->data_only = true;
    result = FREE_CAPACITY_WAIT;
  } else if (context->paid) {
    /* Only locally generated, authenticated protocol commands at the FIFO head
     * may proceed during GRACE. Never skip a prior bulk/stateful cell. */
    result = free_capacity_link_send(&link->limit,
        get_cell_network_size(chan->wide_circ_ids), monotime_absolute_msec());
  } else {
    result = free_capacity_send(&context->limit, &link->limit, 1,
             get_cell_network_size(chan->wide_circ_ids), monotime_absolute_msec());
  }
  if (result == FREE_CAPACITY_OK) {
    context->waiting = false;
    context->data_only = false;
  } else if (result == FREE_CAPACITY_WAIT) {
    context->waiting = true;
    context->wake_ms = deadline_after(monotime_absolute_msec(), 500);
    set_queue_activity(context, false);
    request_wakeup(context->wake_ms);
  } else if (result != FREE_CAPACITY_OK) {
    context->data_only = false;
    if (!circ->marked_for_close)
      circuit_mark_for_close(circ, END_CIRC_REASON_RESOURCELIMIT);
    set_queue_activity(context, false);
  }
  return result;
}

free_capacity_result_t
free_capacity_circuit_send_control(circuit_t *circ, channel_t *chan,
                                    bool payment_control)
{
  return free_capacity_circuit_send_cell(circ, chan, payment_control, CELL_RELAY);
}

free_capacity_result_t
free_capacity_circuit_send(circuit_t *circ, channel_t *chan)
{
  return free_capacity_circuit_send_control(circ, chan, false);
}

void
free_capacity_circuit_queued(circuit_t *circ)
{
  free_capacity_context_t *context = circ->free_capacity;
  if (!context || circ->marked_for_close) return;
  if (context->paid && !free_capacity_paid_data_active(circ)) {
    if (!adopt_held_queues(circ)) {
      context->data_only = false;
      circuit_mark_for_close(circ, END_CIRC_REASON_RESOURCELIMIT);
      set_queue_activity(context, false);
      return;
    }
    if (!context->waiting || context->data_only) {
      context->waiting = true;
      context->data_only = true;
      context->wake_ms = deadline_after(monotime_absolute_msec(), 500);
      request_wakeup(context->wake_ms);
    }
  }
  if (context->waiting) set_queue_activity(context, false);
  request_wakeup(deadline_after(monotime_absolute_msec(),
                                FREE_CAPACITY_QUEUE_AGE_MS));
}

void
free_capacity_circuit_paid(circuit_t *circ)
{
  free_capacity_context_t *context = circ->free_capacity;
  if (!context || !context->confirmed) return;
  context->paid = true;
  context->waiting = false;
  context->data_only = false;
  set_queue_activity(context, true);
}
