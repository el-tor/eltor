/* See LICENSE for licensing information. */
#include "orconfig.h"
#include "core/or/or.h"
#include "feature/payment/payment_circuit.h"
#include "feature/payment/free_capacity_hooks.h"
#include "feature/payment/payment_resources.h"
#include "feature/control/control_payment.h"
#include "core/or/or_circuit_st.h"
#include "core/or/relay_msg_st.h"
#include "core/or/circuitlist.h"
#include "core/or/relay.h"
#include "lib/crypt_ops/crypto_util.h"
#include "lib/ctime/di_ops.h"
#include "lib/evloop/timers.h"
#include "lib/time/compat_time.h"
#include <string.h>

/* One event-loop owner. Financial uniqueness/retention belongs to the durable
 * daemon ledger; these limits bound only live protocol/cache allocations. */
#define PAYMENT_CIRCUIT_MAX 4096u
#define PAYMENT_CIRCUIT_SLOT (16u * 1024u)

typedef struct payment_allocation_t {
  uint64_t period, first_round, deadline_ms;
  uint8_t ids[10][32], allocation[32], nonce[16], request_digest[32];
  uint8_t decision[16];
  payment_circuit_charge_t charges[10];
  payment_circuit_admission_t decision_result;
  uint8_t transmissions;
  bool requested, decided, admitted, expired, operation;
} payment_allocation_t;

struct payment_circuit_t {
  struct or_circuit_t *circ;
  struct payment_circuit_t *next;
  payment_schedule_t schedule;
  protocol_budget_memory_t memory;
  uint64_t revision, commit_ms, query_last_ms;
  uint8_t terms[32], initial_digest[32], binding[32];
  payment_circuit_charge_t fee;
  payment_allocation_t initial, active, next_allocation;
  uint8_t start_digest[32], start_nonce[16], start_transmissions;
  uint8_t setup_queries;
  bool start_operation, query_seen, closed;
};

static payment_circuit_t *profiles;
static tor_timer_t *profile_timer;
static uint32_t profile_count;
static protocol_budget_memory_t timer_memory;
static payment_circuit_event_cb_t event_callback;
static bool timer_dispatching;
static bool construction_enabled, construction_paid;
static payment_profile_policy_t construction_policy;

int
payment_circuit_configure_construction(bool enabled,
                          const payment_profile_policy_t *policy)
{
  uint8_t encoded[PAYMENT_PROFILE_TERMS_LEN];
  if (policy && payment_profile_policy_encode(encoded,sizeof(encoded),policy))
    return -1;
  construction_enabled=enabled;
  construction_paid=enabled && policy;
  memset(&construction_policy,0,sizeof(construction_policy));
  if (policy) construction_policy=*policy;
  return 0;
}

bool
payment_circuit_construction_policy(payment_profile_policy_t *out,
                                     bool *paid_candidate)
{
  if (!out || !paid_candidate) return false;
  *out=construction_policy;
  *paid_candidate=construction_paid;
  return construction_enabled;
}

bool
payment_circuit_requires_payment(const or_circuit_t *circ)
{
  return circ && circ->payment_profile &&
         circ->payment_profile->schedule.committed;
}

static void schedule_timer(uint64_t now_ms);
static int send_allocation_reply(payment_circuit_t *pc,
                                 payment_allocation_t *allocation,
                                 uint64_t now_ms);

static bool
zero_bytes(const uint8_t *p, size_t len)
{
  uint8_t n = 0;
  for (size_t i = 0; i < len; ++i) n |= p[i];
  return n == 0;
}

static uint64_t
remaining(uint64_t deadline, uint64_t now)
{
  return deadline > now ? deadline-now : 0;
}

static bool
terminal(const payment_circuit_t *pc)
{
  return pc->closed || pc->schedule.phase == PAYMENT_SCHEDULE_CLOSED ||
         pc->schedule.phase == PAYMENT_SCHEDULE_EXPIRED;
}

static void
notify(payment_circuit_t *pc, payment_circuit_event_t event)
{
  if (pc->revision == UINT64_MAX) {
    payment_schedule_close(&pc->schedule);
    return;
  }
  ++pc->revision;
  if (event_callback) event_callback(pc->circ, event);
}

void
payment_circuit_set_event_callback(payment_circuit_event_cb_t callback)
{
  event_callback = callback;
}

bool
payment_circuit_present(const or_circuit_t *circ)
{
  return circ && circ->payment_profile && !circ->payment_profile->closed;
}

uint64_t
payment_circuit_revision(const or_circuit_t *circ)
{
  return circ && circ->payment_profile ? circ->payment_profile->revision : 0;
}

static bool
reserve_operation(payment_allocation_t *a)
{
  return payment_resources_operation_reserve(&a->operation);
}

static void
clear_allocation(payment_allocation_t *a)
{
  payment_resources_operation_release(&a->operation);
  memwipe(a, 0, sizeof(*a));
}

static payment_allocation_t *
find_allocation(payment_circuit_t *pc, uint64_t period)
{
  if (period == 0 && pc->schedule.active_period == 0) return &pc->initial;
  if (pc->active.requested && pc->active.period == period) return &pc->active;
  if (pc->next_allocation.requested && pc->next_allocation.period == period)
    return &pc->next_allocation;
  return NULL;
}

static void
consume_charges(payment_circuit_t *pc)
{
  if (!pc->schedule.started) return;
  if (pc->fee.authorization == PAYMENT_CIRCUIT_AUTHORIZED)
    pc->fee.authorization = PAYMENT_CIRCUIT_CONSUMED;
  payment_allocation_t *allocations[] = {
    &pc->initial, &pc->active, &pc->next_allocation
  };
  for (size_t a = 0; a < 3; ++a) {
    payment_allocation_t *p = allocations[a];
    if (!p->admitted) continue;
    for (size_t i = 0; i < 10; ++i) {
      if (p->first_round+i <= pc->schedule.current_round &&
          p->charges[i].authorization == PAYMENT_CIRCUIT_AUTHORIZED)
        p->charges[i].authorization = PAYMENT_CIRCUIT_CONSUMED;
    }
  }
}

static void
observe_schedule(payment_circuit_t *pc, payment_schedule_phase_t old_phase,
                 uint64_t old_round, uint64_t old_period)
{
  consume_charges(pc);
  if (pc->schedule.phase == PAYMENT_SCHEDULE_ACTIVE)
    free_capacity_circuit_paid(TO_CIRCUIT(pc->circ));
  if (pc->schedule.active_period != old_period) {
    clear_allocation(&pc->active);
    pc->active = pc->next_allocation;
    /* Move operation ownership, rather than releasing the admitted record. */
    memwipe(&pc->next_allocation, 0, sizeof(pc->next_allocation));
  }
  if ((pc->schedule.phase != old_phase ||
       pc->schedule.current_round != old_round) &&
      (pc->schedule.phase == PAYMENT_SCHEDULE_ACTIVE ||
       pc->schedule.phase == PAYMENT_SCHEDULE_GRACE ||
       pc->schedule.phase == PAYMENT_SCHEDULE_EXPIRED ||
       pc->schedule.phase == PAYMENT_SCHEDULE_CLOSED)) {
    payment_circuit_event_t event = PAYMENT_CIRCUIT_EVENT_ROUND_ACTIVE;
    if (pc->schedule.phase == PAYMENT_SCHEDULE_GRACE)
      event = PAYMENT_CIRCUIT_EVENT_GRACE;
    else if (pc->schedule.phase == PAYMENT_SCHEDULE_EXPIRED)
      event = PAYMENT_CIRCUIT_EVENT_EXPIRED;
    else if (pc->schedule.phase == PAYMENT_SCHEDULE_CLOSED)
      event = PAYMENT_CIRCUIT_EVENT_CLOSED;
    notify(pc, event);
  }
}

void
payment_circuit_close(or_circuit_t *circ)
{
  if (!circ || !circ->payment_profile) return;
  payment_circuit_t *pc = circ->payment_profile;
  if (pc->closed) return;
  pc->closed = true;
  payment_schedule_close(&pc->schedule);
  notify(pc, PAYMENT_CIRCUIT_EVENT_CLOSED);
  schedule_timer(monotime_absolute_msec());
}

void
payment_circuit_free(or_circuit_t *circ)
{
  if (!circ || !circ->payment_profile) return;
  payment_circuit_close(circ);
  payment_circuit_t *pc = circ->payment_profile;
  payment_circuit_t **link = &profiles;
  while (*link && *link != pc) link = &(*link)->next;
  if (*link) *link = pc->next;
  clear_allocation(&pc->initial);
  clear_allocation(&pc->active);
  clear_allocation(&pc->next_allocation);
  payment_resources_operation_release(&pc->start_operation);
  --profile_count;
  protocol_budget_memory_t memory = pc->memory;
  memwipe(pc, 0, sizeof(*pc));
  tor_free(pc);
  (void)payment_resources_release(&memory);
  circ->payment_profile = NULL;
  if (!profiles) {
    timer_free(profile_timer);
    (void)payment_resources_release(&timer_memory);
  } else schedule_timer(monotime_absolute_msec());
}

payment_circuit_result_t
payment_circuit_attach(or_circuit_t *circ,
                       const payment_profile_policy_t *policy,
                       const uint8_t ids[10][32],
                       const uint8_t fee_hash[32],
                       uint64_t constructed_ms, uint64_t now_ms)
{
  if (!circ || circ->base_.marked_for_close)
    return PAYMENT_CIRCUIT_CLOSED;
  if (circ->payment_profile) return PAYMENT_CIRCUIT_CONFLICT;
  if (!circ->payment_export_requested || !circ->payment_keys || !policy ||
      !fee_hash || !payment_profile_ids_valid(ids) || now_ms < constructed_ms ||
      (policy->initial_handshake_fee_msat && zero_bytes(fee_hash, 32)))
    return PAYMENT_CIRCUIT_INVALID;
  if (profile_count >= PAYMENT_CIRCUIT_MAX ||
      sizeof(payment_circuit_t) > PAYMENT_CIRCUIT_SLOT)
    return PAYMENT_CIRCUIT_CAPACITY;
  payment_schedule_t schedule;
  if (payment_schedule_init(&schedule, policy, constructed_ms) < 0)
    return PAYMENT_CIRCUIT_INVALID;
  payment_schedule_tick(&schedule, now_ms);
  if (schedule.phase == PAYMENT_SCHEDULE_EXPIRED && !circ->base_.free_capacity)
    return PAYMENT_CIRCUIT_EXPIRED;
  control_payment_init();
  protocol_budget_memory_t memory = {0};
  if (payment_resources_reserve(&memory, sizeof(payment_circuit_t)) !=
      PROTOCOL_BUDGET_OK)
    return PAYMENT_CIRCUIT_CAPACITY;
  if (!profile_timer && !timer_memory.active &&
      payment_resources_reserve(&timer_memory,
        timer_memory_cost() + sizeof(timer_memory)) != PROTOCOL_BUDGET_OK) {
    (void)payment_resources_release(&memory);
    return PAYMENT_CIRCUIT_CAPACITY;
  }
  if (control_payment_register(TO_CIRCUIT(circ), CONTROL_PAYMENT_RELAY,
                                1, false) < 0) {
    (void)payment_resources_release(&memory);
    if (!profiles)
      (void)payment_resources_release(&timer_memory);
    return PAYMENT_CIRCUIT_CAPACITY;
  }
  payment_circuit_t *pc = tor_malloc_zero(sizeof(*pc));
  pc->memory = memory;
  memset(&memory, 0, sizeof(memory));
  pc->circ = circ;
  pc->schedule = schedule;
  pc->revision = 1;
  memcpy(pc->binding, circ->payment_keys->binding, 32);
  payment_profile_terms_digest(pc->terms, policy);
  payment_profile_initial_digest(pc->initial_digest, pc->binding, pc->terms, ids);
  memcpy(pc->initial.ids, ids, 320);
  memcpy(pc->initial.allocation, pc->initial_digest, 32);
  pc->initial.first_round = 1;
  pc->initial.deadline_ms = constructed_ms+policy->setup_timeout_ms;
  pc->fee.amount_msat = policy->initial_handshake_fee_msat;
  if (pc->fee.amount_msat) memcpy(pc->fee.payment_hash, fee_hash, 32);
  for (size_t i = 0; i < 10; ++i)
    pc->initial.charges[i].amount_msat = policy->rate_msat;
  pc->next = profiles;
  profiles = pc;
  ++profile_count;
  circ->payment_profile = pc;
  if (event_callback) event_callback(circ, PAYMENT_CIRCUIT_EVENT_REGISTERED);
  schedule_timer(now_ms);
  return PAYMENT_CIRCUIT_OK;
}

static uint64_t
next_deadline(const payment_circuit_t *pc)
{
  if (terminal(pc)) return UINT64_MAX;
  uint64_t deadline;
  const payment_schedule_t *s = &pc->schedule;
  if (!s->started) {
    deadline = s->constructed_ms+s->policy.setup_timeout_ms;
  } else {
    uint64_t elapsed = s->last_ms-s->t0_ms;
    uint64_t boundary = elapsed/PAYMENT_PROFILE_ROUND_MS;
    if (s->phase == PAYMENT_SCHEDULE_GRACE)
      deadline = s->t0_ms+boundary*PAYMENT_PROFILE_ROUND_MS+s->policy.grace_ms;
    else
      deadline = s->t0_ms+(boundary+1)*PAYMENT_PROFILE_ROUND_MS;
    uint64_t hard_age = s->t0_ms+s->policy.max_age_ms;
    if (hard_age < deadline) deadline = hard_age;
  }
  const payment_allocation_t *a = &pc->next_allocation;
  if (a->requested && !a->decided && !a->expired && a->deadline_ms < deadline)
    deadline = a->deadline_ms;
  return deadline;
}

static void
profile_timer_callback(tor_timer_t *timer, void *arg, const monotime_t *now)
{
  (void)timer; (void)arg; (void)now;
  uint64_t now_ms = monotime_absolute_msec();
  timer_dispatching = true;
  for (payment_circuit_t *pc = profiles; pc; pc = pc->next)
    payment_circuit_tick(pc->circ, now_ms);
  timer_dispatching = false;
  schedule_timer(now_ms);
}

static void
schedule_timer(uint64_t now_ms)
{
  if (timer_dispatching) return;
  uint64_t next = UINT64_MAX;
  for (payment_circuit_t *pc = profiles; pc; pc = pc->next) {
    uint64_t deadline = next_deadline(pc);
    if (deadline < next) next = deadline;
  }
  if (next == UINT64_MAX) {
    if (profile_timer) timer_disable(profile_timer);
    return;
  }
  if (!profile_timer) profile_timer = timer_new(profile_timer_callback, NULL);
  uint64_t delay = remaining(next, now_ms);
  /* One shared timer, with a bounded wake delay even for large test policies. */
  if (delay > PAYMENT_PROFILE_ROUND_MS) delay = PAYMENT_PROFILE_ROUND_MS;
  if (!delay) delay = 1;
  struct timeval tv = { (time_t)(delay/1000), (suseconds_t)(delay%1000)*1000 };
  timer_schedule(profile_timer, &tv);
}

void
payment_circuit_tick(or_circuit_t *circ, uint64_t now_ms)
{
  if (!payment_circuit_present(circ)) return;
  payment_circuit_t *pc = circ->payment_profile;
  payment_schedule_phase_t old_phase = pc->schedule.phase;
  uint64_t old_round = pc->schedule.current_round;
  uint64_t old_period = pc->schedule.active_period;
  payment_schedule_tick(&pc->schedule, now_ms);
  observe_schedule(pc, old_phase, old_round, old_period);
  payment_allocation_t *a = &pc->next_allocation;
  if (!terminal(pc) && a->requested && !a->decided && !a->expired &&
      now_ms >= a->deadline_ms) {
    a->expired = true;
    send_allocation_reply(pc, a, now_ms);
    notify(pc, PAYMENT_CIRCUIT_EVENT_RENEW_REFUSED);
  }
  if (terminal(pc) && (pc->schedule.committed || !circ->base_.free_capacity) &&
      !circ->base_.marked_for_close)
    circuit_mark_for_close(TO_CIRCUIT(circ), END_CIRC_REASON_TIMEOUT);
  schedule_timer(now_ms);
}

bool
payment_circuit_paid_active(const or_circuit_t *circ)
{
  return payment_circuit_present(circ) &&
         circ->payment_profile->schedule.phase == PAYMENT_SCHEDULE_ACTIVE;
}

bool
payment_circuit_data_active(const or_circuit_t *circ, uint64_t now_ms)
{
  if (!payment_circuit_present(circ)) return false;
  const payment_circuit_t *pc=circ->payment_profile;
  if (!pc->schedule.committed || now_ms<pc->schedule.last_ms) return false;
  payment_schedule_t projected=pc->schedule;
  payment_schedule_tick(&projected,now_ms);
  /* Projection may revoke traffic permission, but must never grant a due
   * activation before the real timer consumes/announces the authorization. */
  return pc->schedule.phase==PAYMENT_SCHEDULE_ACTIVE &&
         projected.phase==PAYMENT_SCHEDULE_ACTIVE &&
         projected.current_round==pc->schedule.current_round &&
         projected.active_period==pc->schedule.active_period;
}

static int
send_message(payment_circuit_t *pc, const payment_profile_message_t *m)
{
  if (pc->closed || pc->circ->base_.marked_for_close || !pc->circ->payment_keys)
    return 0;
  uint8_t wire[PAYMENT_PROFILE_WIRE_LEN];
  const uint8_t *key = m->command == PAYMENT_PROFILE_RENEWED ?
    pc->circ->payment_keys->renew_reply : pc->circ->payment_keys->start_reply;
  if (payment_profile_encode(wire, sizeof(wire), m, key, pc->binding) != 0)
    return -END_CIRC_REASON_INTERNAL;
  return relay_send_command_from_edge(0, TO_CIRCUIT(pc->circ), m->command,
                          (const char *)wire, sizeof(wire), NULL);
}

static uint64_t
elapsed_ms(const payment_circuit_t *pc, uint64_t now_ms)
{
  return pc->schedule.started && now_ms >= pc->schedule.t0_ms ?
         now_ms-pc->schedule.t0_ms : 0;
}

static int
send_commit_reply(payment_circuit_t *pc, const uint8_t nonce[16],
                  const uint8_t digest[32], uint8_t status, uint64_t now_ms)
{
  payment_profile_message_t m = { .command = PAYMENT_PROFILE_COMMITTED };
  payment_profile_committed_t *r = &m.u.committed;
  r->status = status;
  memcpy(r->nonce, nonce, 16); memcpy(r->request_digest, digest, 32);
  if (!status) {
    memcpy(r->terms, pc->terms, 32);
    memcpy(r->allocation, pc->initial_digest, 32);
  }
  if (!pc->schedule.started && status < 4)
    r->setup_remaining_ms = (uint32_t)remaining(pc->initial.deadline_ms, now_ms);
  return send_message(pc, &m);
}

static int
send_renew_reply(payment_circuit_t *pc, const payment_allocation_t *a,
                 uint8_t status, uint64_t now_ms)
{
  payment_profile_message_t m = { .command = PAYMENT_PROFILE_RENEWED };
  payment_profile_renewed_t *r = &m.u.renewed;
  r->status = status; r->period = a->period; r->first_round = a->first_round;
  memcpy(r->nonce, a->nonce, 16); memcpy(r->request_digest, a->request_digest, 32);
  memcpy(r->terms, pc->terms, 32);
  if (status < 2) memcpy(r->allocation, a->allocation, 32);
  r->elapsed_ms = elapsed_ms(pc, now_ms);
  if (a->period && a->period <= UINT64_MAX/(10*UINT64_C(60000)) &&
      a->first_round == a->period*10+1) {
    r->activation_ms = a->period*10*UINT64_C(60000);
    r->admit_before_ms = r->activation_ms-PAYMENT_PROFILE_ROUND_MS;
  }
  return send_message(pc, &m);
}

static int
send_allocation_reply(payment_circuit_t *pc, payment_allocation_t *a,
                       uint64_t now_ms)
{
  if (!a->period) {
    uint8_t status = a->admitted ? 0 : a->expired ? 4 :
      a->decision_result == PAYMENT_CIRCUIT_ID_CONFLICT ? 2 : 3;
    return send_commit_reply(pc, a->nonce, a->request_digest, status, now_ms);
  }
  uint8_t status = a->admitted ?
    (pc->schedule.active_period == a->period ? 1 : 0) : a->expired ? 3 :
    a->decision_result == PAYMENT_CIRCUIT_ID_CONFLICT ? 7 : 8;
  return send_renew_reply(pc, a, status, now_ms);
}

static uint64_t
round_remaining(const payment_circuit_t *pc, uint64_t now_ms)
{
  if (!pc->schedule.started || terminal(pc)) return 0;
  uint64_t end = pc->schedule.t0_ms+
                pc->schedule.current_round*PAYMENT_PROFILE_ROUND_MS;
  return remaining(end, now_ms);
}

static uint64_t
enforcement_remaining(const payment_circuit_t *pc, uint64_t now_ms)
{
  if (!pc->schedule.started || terminal(pc)) return 0;
  uint64_t end = pc->schedule.t0_ms+pc->schedule.current_round*
                 PAYMENT_PROFILE_ROUND_MS;
  if (pc->schedule.phase == PAYMENT_SCHEDULE_GRACE)
    end -= PAYMENT_PROFILE_ROUND_MS;
  uint64_t hard_age = pc->schedule.t0_ms+pc->schedule.policy.max_age_ms;
  if (end <= UINT64_MAX-pc->schedule.policy.grace_ms)
    end += pc->schedule.policy.grace_ms;
  else end = UINT64_MAX;
  if (hard_age < end) end = hard_age;
  return remaining(end, now_ms);
}

static int
send_start_reply(payment_circuit_t *pc, const payment_profile_start_t *request,
                  const uint8_t digest[32], bool conflict, uint64_t now_ms)
{
  payment_profile_message_t m = { .command = PAYMENT_PROFILE_STARTED_STATUS };
  payment_profile_started_t *r = &m.u.started;
  r->state = conflict ? 7 : (uint8_t)pc->schedule.phase;
  memcpy(r->nonce, request->nonce, 16);
  memcpy(r->request_digest, digest, 32);
  if (pc->schedule.committed) {
    memcpy(r->terms, pc->terms, 32);
    memcpy(r->allocation, pc->initial_digest, 32);
  }
  r->round = pc->schedule.current_round;
  r->elapsed_ms = elapsed_ms(pc, now_ms);
  r->round_remaining_ms = (uint32_t)round_remaining(pc, now_ms);
  r->enforcement_remaining_ms = (uint32_t)enforcement_remaining(pc, now_ms);
  if (!pc->schedule.started && !terminal(pc))
    r->setup_remaining_ms = (uint32_t)remaining(pc->initial.deadline_ms, now_ms);
  r->revision = pc->revision;
  return send_message(pc, &m);
}

static int
handle_commit(payment_circuit_t *pc, const payment_profile_commit_t *request,
               const uint8_t digest[32], uint64_t now_ms)
{
  uint8_t q[32];
  payment_profile_terms_digest(q, &request->policy);
  if (tor_memneq(q, pc->terms, 32))
    return send_commit_reply(pc, request->nonce, digest, 1, now_ms);
  if (tor_memneq(request->allocation, pc->initial_digest, 32))
    return send_commit_reply(pc, request->nonce, digest, 2, now_ms);
  payment_allocation_t *a = &pc->initial;
  if (a->requested) {
    if (tor_memneq(a->request_digest, digest, 32))
      return send_commit_reply(pc, request->nonce, digest, 2, now_ms);
    if (a->transmissions >= 4) return 0;
    ++a->transmissions;
    if (a->decided || a->expired) return send_allocation_reply(pc, a, now_ms);
    return 0;
  }
  if (!reserve_operation(a))
    return send_commit_reply(pc, request->nonce, digest, 3, now_ms);
  a->requested = true; a->transmissions = 1;
  memcpy(a->nonce, request->nonce, 16);
  memcpy(a->request_digest, digest, 32);
  notify(pc, PAYMENT_CIRCUIT_EVENT_ADMISSION_PENDING);
  return 0;
}

static bool
reuses_ids(const payment_circuit_t *pc, const uint8_t ids[10][32])
{
  const payment_allocation_t *records[] = { &pc->initial, &pc->active };
  for (size_t r = 0; r < 2; ++r) {
    if (r && !records[r]->admitted) continue;
    for (size_t i = 0; i < 10; ++i)
      for (size_t j = 0; j < 10; ++j)
        if (tor_memeq(ids[i], records[r]->ids[j], 32)) return true;
  }
  return false;
}

static int
handle_renew(payment_circuit_t *pc, const payment_profile_renew_t *request,
              const uint8_t digest[32], uint64_t now_ms)
{
  payment_allocation_t reply = {0};
  reply.period = request->period; reply.first_round = request->first_round;
  memcpy(reply.nonce, request->nonce, 16);
  memcpy(reply.request_digest, digest, 32);
  payment_allocation_t *known = find_allocation(pc, request->period);
  if (known && known->requested) {
    if (tor_memneq(known->request_digest, digest, 32))
      return send_renew_reply(pc, &reply, 4, now_ms);
    if (known->transmissions >= 4) return 0;
    ++known->transmissions;
    if (known->admitted || known->decided || known->expired)
      return send_allocation_reply(pc, known, now_ms);
    return 0;
  }
  if (!pc->schedule.started || !pc->schedule.committed)
    return send_renew_reply(pc, &reply, 9, now_ms);
  payment_allocation_t *active = pc->schedule.active_period ?
                                &pc->active : &pc->initial;
  int check = payment_profile_renew_check(request, &pc->schedule.policy,
                  pc->schedule.active_period+1, pc->terms, active->allocation);
  uint8_t refusal = check == PAYMENT_PROFILE_ERR_TERMS ? 6 :
    check == PAYMENT_PROFILE_ERR_PARENT ? 5 :
    check == PAYMENT_PROFILE_ERR_POLICY ? 2 : 7;
  if (check || reuses_ids(pc, request->ids))
    return send_renew_reply(pc, &reply, check ? refusal : 7, now_ms);
  uint64_t deadline = pc->schedule.t0_ms+request->activation_ms-
                      PAYMENT_PROFILE_ROUND_MS;
  if (now_ms >= deadline) return send_renew_reply(pc, &reply, 3, now_ms);
  payment_allocation_t *a = &pc->next_allocation;
  if (a->requested || !reserve_operation(a))
    return send_renew_reply(pc, &reply, 8, now_ms);
  a->period = request->period; a->first_round = request->first_round;
  a->deadline_ms = deadline; a->requested = true; a->transmissions = 1;
  memcpy(a->nonce, request->nonce, 16);
  memcpy(a->request_digest, digest, 32);
  memcpy(a->ids, request->ids, 320);
  for (size_t i = 0; i < 10; ++i)
    a->charges[i].amount_msat = pc->schedule.policy.rate_msat;
  /* Compute from the canonical request, not a native struct. */
  payment_profile_message_t m = { .command = PAYMENT_PROFILE_RENEW };
  m.u.renew = *request;
  uint8_t wire[PAYMENT_PROFILE_WIRE_LEN];
  payment_profile_encode(wire, sizeof(wire), &m,
                          pc->circ->payment_keys->renew_request, pc->binding);
  payment_profile_allocation_digest(a->allocation, pc->binding, wire,
                                     sizeof(wire));
  notify(pc, PAYMENT_CIRCUIT_EVENT_ADMISSION_PENDING);
  schedule_timer(now_ms);
  return 0;
}

static int
handle_start(payment_circuit_t *pc, const payment_profile_start_t *request,
              const uint8_t digest[32], uint64_t now_ms)
{
  bool conflict = tor_memneq(request->terms, pc->terms, 32) ||
                  tor_memneq(request->allocation, pc->initial_digest, 32);
  if (!request->action) {
    if (!pc->schedule.committed) conflict = true;
    else if (pc->start_operation) {
      if (tor_memneq(pc->start_digest, digest, 32)) conflict = true;
      else if (pc->start_transmissions >= 4) return 0;
      else ++pc->start_transmissions;
    } else if (!conflict) {
      if (!payment_resources_operation_reserve(&pc->start_operation))
        return 0;
      pc->start_transmissions = 1;
      memcpy(pc->start_digest, digest, 32);
      memcpy(pc->start_nonce, request->nonce, 16);
      payment_schedule_phase_t old_phase = pc->schedule.phase;
      uint64_t old_round = pc->schedule.current_round;
      uint64_t old_period = pc->schedule.active_period;
      payment_schedule_start(&pc->schedule, now_ms);
      notify(pc, PAYMENT_CIRCUIT_EVENT_START_REQUESTED);
      observe_schedule(pc, old_phase, old_round, old_period);
      schedule_timer(now_ms);
    }
  } else {
    if ((pc->query_seen && (now_ms < pc->query_last_ms ||
         now_ms-pc->query_last_ms < 1000)) ||
        (!pc->schedule.started && pc->setup_queries >= 16)) return 0;
    pc->query_seen = true; pc->query_last_ms = now_ms;
    if (!pc->schedule.started) ++pc->setup_queries;
  }
  return send_start_reply(pc, request, digest, conflict, now_ms);
}

static payment_circuit_result_t
observation_status(const payment_circuit_t *pc, uint64_t now_ms)
{
  if (now_ms < pc->schedule.last_ms) return PAYMENT_CIRCUIT_INVALID;
  payment_schedule_t projected = pc->schedule;
  payment_schedule_tick(&projected, now_ms);
  if (projected.phase == PAYMENT_SCHEDULE_EXPIRED ||
      projected.phase == PAYMENT_SCHEDULE_CLOSED)
    return PAYMENT_CIRCUIT_EXPIRED;
  if (projected.phase != pc->schedule.phase ||
      projected.current_round != pc->schedule.current_round ||
      projected.active_period != pc->schedule.active_period ||
      projected.started != pc->schedule.started)
    return PAYMENT_CIRCUIT_OBSERVATION_PENDING;
  return PAYMENT_CIRCUIT_OK;
}

int
payment_circuit_handle_relay(or_circuit_t *circ, const relay_msg_t *msg,
                             uint64_t now_ms)
{
  if (!payment_circuit_present(circ) || !msg || msg->stream_id ||
      msg->is_relay_early || !circ->payment_keys) return 0;
  payment_circuit_t *pc = circ->payment_profile;
  payment_profile_command_t command = (payment_profile_command_t)msg->command;
  if (command != PAYMENT_PROFILE_COMMIT && command != PAYMENT_PROFILE_RENEW &&
      command != PAYMENT_PROFILE_START_STATUS) return 0;
  const uint8_t *key = command == PAYMENT_PROFILE_RENEW ?
    circ->payment_keys->renew_request : circ->payment_keys->start_request;
  payment_profile_message_t request;
  int decoded = payment_profile_decode(&request, command, msg->body,
                                       msg->length, key, pc->binding);
  /* QUERY must not drive deferred activation/consumption. An independent timer
   * advances due transitions; until then suppress an incoherent observation. */
  if (!decoded && command == PAYMENT_PROFILE_START_STATUS &&
      request.u.start.action == 1) {
    if (observation_status(pc, now_ms) != PAYMENT_CIRCUIT_OK) return 0;
  } else {
    payment_circuit_tick(circ, now_ms);
    if (terminal(pc)) {
      if (!decoded && !pc->closed && !pc->schedule.committed &&
          command == PAYMENT_PROFILE_COMMIT) {
        uint8_t expired_digest[32];
        payment_profile_request_digest(expired_digest,command,msg->body,msg->length);
        return send_commit_reply(pc,request.u.commit.nonce,expired_digest,4,now_ms);
      }
      return 0;
    }
  }
  uint8_t digest[32];
  if (decoded == PAYMENT_PROFILE_ERR_SEQUENCE &&
      command == PAYMENT_PROFILE_RENEW) {
    payment_allocation_t reply = {0};
    for (size_t i = 0; i < 8; ++i) {
      reply.period = (reply.period << 8) | msg->body[2+i];
      reply.first_round = (reply.first_round << 8) | msg->body[10+i];
    }
    memcpy(reply.nonce, msg->body+19, 16);
    payment_profile_request_digest(reply.request_digest, command,
                                   msg->body, msg->length);
    return send_renew_reply(pc, &reply, 7, now_ms);
  }
  if (decoded == PAYMENT_PROFILE_ERR_POLICY &&
      command == PAYMENT_PROFILE_COMMIT) {
    payment_profile_request_digest(digest, command, msg->body, msg->length);
    return send_commit_reply(pc, msg->body+2, digest, 1, now_ms);
  }
  if (decoded) return 0;
  payment_profile_request_digest(digest, command, msg->body, msg->length);
  switch (command) {
    case PAYMENT_PROFILE_COMMIT:
      return handle_commit(pc, &request.u.commit, digest, now_ms);
    case PAYMENT_PROFILE_RENEW:
      return handle_renew(pc, &request.u.renew, digest, now_ms);
    case PAYMENT_PROFILE_START_STATUS:
      return handle_start(pc, &request.u.start, digest, now_ms);
    case PAYMENT_PROFILE_RENEWED:
    case PAYMENT_PROFILE_COMMITTED:
    case PAYMENT_PROFILE_STARTED_STATUS:
    default:
      return 0;
  }
}

static payment_circuit_result_t
snapshot(const or_circuit_t *circ, uint64_t period, uint64_t now_ms,
          bool admission, payment_circuit_snapshot_t *out)
{
  if (!out) return PAYMENT_CIRCUIT_INVALID;
  memset(out, 0, sizeof(*out));
  if (!payment_circuit_present(circ)) return PAYMENT_CIRCUIT_CLOSED;
  payment_circuit_t *pc = circ->payment_profile;
  /* A GET cannot execute a deferred timer's activation/consumption. Refuse an
   * incoherent snapshot until that timer runs, rather than combining a cached
   * round with a later clock or inventing an ACTIVE transition in a copy. */
  payment_circuit_result_t observed = observation_status(pc, now_ms);
  if (observed != PAYMENT_CIRCUIT_OK) return observed;
  payment_allocation_t *a = find_allocation(pc, period);
  if (!a || !a->requested) return pc->schedule.committed ?
    PAYMENT_CIRCUIT_UNKNOWN_PERIOD : PAYMENT_CIRCUIT_UNCONFIRMED;
  if (admission) {
    if (a->decided || a->expired || now_ms >= a->deadline_ms)
      return PAYMENT_CIRCUIT_UNKNOWN_PERIOD;
  } else if (!a->admitted) return PAYMENT_CIRCUIT_UNCONFIRMED;
  out->policy = pc->schedule.policy;
  memcpy(out->terms, pc->terms, 32);
  memcpy(out->initial_allocation, pc->initial_digest, 32);
  memcpy(out->allocation, a->allocation, 32);
  memcpy(out->circuit_binding, pc->binding, 32);
  memcpy(out->request_digest, a->request_digest, 32);
  out->revision = pc->revision; out->period = period;
  out->first_round = a->first_round;
  out->current_round = pc->schedule.current_round;
  out->elapsed_ms = elapsed_ms(pc, now_ms);
  out->constructed_elapsed_ms=now_ms-pc->schedule.constructed_ms;
  out->commit_clock_available=pc->schedule.committed;
  if (out->commit_clock_available) out->commit_elapsed_ms=now_ms-pc->commit_ms;
  out->phase = pc->schedule.phase; out->pending = admission;
  if (!pc->schedule.started && !terminal(pc))
    out->setup_remaining_ms = remaining(pc->initial.deadline_ms, now_ms);
  out->enforcement_remaining_ms = enforcement_remaining(pc, now_ms);
  out->admission_remaining_ms = remaining(a->deadline_ms, now_ms);
  out->fee = pc->fee;
  if (admission) {
    memset(out->fee.decision, 0, 16);
    out->fee.authorization = PAYMENT_CIRCUIT_AUTH_NONE;
  }
  for (size_t i = 0; i < 10; ++i) {
    payment_circuit_round_t *r = &out->rounds[i];
    memcpy(r->payment_id, a->ids[i], 32);
    r->round = a->first_round+i;
    r->charge = a->charges[i];
    if (admission) {
      memset(r->charge.decision, 0, 16);
      r->charge.authorization = PAYMENT_CIRCUIT_AUTH_NONE;
      continue;
    }
    if (r->round == 1) {
      r->window_available = true;
      r->opens_in_ms = remaining(pc->commit_ms, now_ms);
      r->closes_in_ms = remaining(pc->initial.deadline_ms, now_ms);
    } else if (pc->schedule.started) {
      uint64_t start = pc->schedule.t0_ms+
                       (r->round-1)*PAYMENT_PROFILE_ROUND_MS;
      r->window_available = true;
      r->opens_in_ms = remaining(start-PAYMENT_PROFILE_ROUND_MS, now_ms);
      r->closes_in_ms = remaining(start+pc->schedule.policy.grace_ms, now_ms);
    }
  }
  return PAYMENT_CIRCUIT_OK;
}

payment_circuit_result_t
payment_circuit_get_admission(const or_circuit_t *circ, uint64_t period,
                              uint64_t now_ms, payment_circuit_snapshot_t *out)
{
  return snapshot(circ, period, now_ms, true, out);
}

payment_circuit_result_t
payment_circuit_get_registration(const or_circuit_t *circ, uint64_t period,
                                 uint64_t now_ms, payment_circuit_snapshot_t *out)
{
  return snapshot(circ, period, now_ms, false, out);
}

payment_circuit_result_t
payment_circuit_decide(or_circuit_t *circ, uint64_t period,
                       const uint8_t digest[32], const uint8_t decision[16],
                       payment_circuit_admission_t result, uint64_t now_ms)
{
  if (!payment_circuit_present(circ)) return PAYMENT_CIRCUIT_CLOSED;
  if (!digest || !decision || zero_bytes(decision, 16) ||
      (unsigned)result > PAYMENT_CIRCUIT_NO_CAPACITY) return PAYMENT_CIRCUIT_INVALID;
  payment_circuit_t *pc = circ->payment_profile;
  payment_allocation_t *a = find_allocation(pc, period);
  if (!a || !a->requested) return PAYMENT_CIRCUIT_UNKNOWN_PERIOD;
  if (tor_memneq(a->request_digest, digest, 32)) return PAYMENT_CIRCUIT_CONFLICT;
  if (a->decided) return a->decision_result == result &&
    tor_memeq(a->decision, decision, 16) ? PAYMENT_CIRCUIT_OK :
                                       PAYMENT_CIRCUIT_CONFLICT;
  payment_circuit_tick(circ, now_ms);
  if (terminal(pc) || a->expired || now_ms >= a->deadline_ms)
    return PAYMENT_CIRCUIT_EXPIRED;
  if (result == PAYMENT_CIRCUIT_RESERVED) {
    int r = period ? payment_schedule_admit_next(&pc->schedule, period, now_ms) :
                     payment_schedule_commit(&pc->schedule, now_ms);
    if (r < 0) return PAYMENT_CIRCUIT_EXPIRED;
    a->admitted = true;
    if (!period) pc->commit_ms = now_ms;
  }
  a->decided = true; a->decision_result = result;
  memcpy(a->decision, decision, 16);
  notify(pc, a->admitted ? (period ? PAYMENT_CIRCUIT_EVENT_RENEW_ADMITTED :
                              PAYMENT_CIRCUIT_EVENT_COMMITTED) :
                            PAYMENT_CIRCUIT_EVENT_RENEW_REFUSED);
  int sent = send_allocation_reply(pc, a, now_ms);
  if (sent < 0) circuit_mark_for_close(TO_CIRCUIT(circ), -sent);
  schedule_timer(now_ms);
  return PAYMENT_CIRCUIT_OK;
}

payment_circuit_result_t
payment_circuit_authorize(or_circuit_t *circ, uint64_t round,
                          const payment_circuit_charge_t *authorization,
                          uint64_t now_ms)
{
  if (!payment_circuit_present(circ)) return PAYMENT_CIRCUIT_CLOSED;
  if (!authorization || zero_bytes(authorization->decision, 16) ||
      (authorization->amount_msat && zero_bytes(authorization->payment_hash, 32)) ||
      (!authorization->amount_msat && !zero_bytes(authorization->payment_hash, 32)))
    return PAYMENT_CIRCUIT_INVALID;
  payment_circuit_t *pc = circ->payment_profile;
  if (!pc->schedule.committed) return PAYMENT_CIRCUIT_UNCONFIRMED;
  payment_circuit_charge_t *target;
  if (!round) target = &pc->fee;
  else {
    payment_allocation_t *a = find_allocation(pc, (round-1)/10);
    if (!a || !a->admitted) return PAYMENT_CIRCUIT_UNKNOWN_PERIOD;
    target = &a->charges[(round-1)%10];
  }
  if (target->authorization != PAYMENT_CIRCUIT_AUTH_NONE) {
    return target->amount_msat == authorization->amount_msat &&
      tor_memeq(target->decision, authorization->decision, 16) &&
      tor_memeq(target->payment_hash, authorization->payment_hash, 32) &&
      tor_memeq(target->record_digest, authorization->record_digest, 32) ?
      PAYMENT_CIRCUIT_OK : PAYMENT_CIRCUIT_CONFLICT;
  }
  const payment_allocation_t *records[] = {
    &pc->initial, &pc->active, &pc->next_allocation
  };
  if (target != &pc->fee && pc->fee.authorization != PAYMENT_CIRCUIT_AUTH_NONE &&
      tor_memeq(pc->fee.decision, authorization->decision, 16))
    return PAYMENT_CIRCUIT_CONFLICT;
  for (size_t a = 0; a < 3; ++a) {
    for (size_t i = 0; i < 10; ++i) {
      const payment_circuit_charge_t *c = &records[a]->charges[i];
      if (c != target && c->authorization != PAYMENT_CIRCUIT_AUTH_NONE &&
          tor_memeq(c->decision, authorization->decision, 16))
        return PAYMENT_CIRCUIT_CONFLICT;
    }
  }
  if (target->amount_msat != authorization->amount_msat ||
      (!round && target->amount_msat &&
       tor_memneq(target->payment_hash, authorization->payment_hash, 32)))
    return PAYMENT_CIRCUIT_INVALID;
  payment_circuit_tick(circ, now_ms);
  if (terminal(pc)) return PAYMENT_CIRCUIT_EXPIRED;
  /* A due boundary can move the next allocation into the active slot. Resolve
   * its charge again after ticking so the authorization never lands in the
   * cleared source of that move. Exact retained replay above remains inert. */
  if (round) {
    payment_allocation_t *a = find_allocation(pc, (round-1)/10);
    if (!a || !a->admitted) return PAYMENT_CIRCUIT_UNKNOWN_PERIOD;
    target = &a->charges[(round-1)%10];
  }
  payment_schedule_phase_t old_phase = pc->schedule.phase;
  uint64_t old_round = pc->schedule.current_round;
  uint64_t old_period = pc->schedule.active_period;
  if (payment_schedule_authorize(&pc->schedule, round, now_ms) < 0)
    return PAYMENT_CIRCUIT_EXPIRED;
  *target = *authorization;
  target->authorization = PAYMENT_CIRCUIT_AUTHORIZED;
  notify(pc, PAYMENT_CIRCUIT_EVENT_AUTHORIZED);
  observe_schedule(pc, old_phase, old_round, old_period);
  schedule_timer(now_ms);
  return PAYMENT_CIRCUIT_OK;
}
