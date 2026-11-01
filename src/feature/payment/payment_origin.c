/* Copyright (c) 2026, The El Tor Project. */
/* See LICENSE for licensing information. */
#include "orconfig.h"
#include "core/or/or.h"
#include "app/config/config.h"
#include "app/config/or_options_st.h"
#include "core/or/origin_circuit_st.h"
#include "core/or/crypt_path_st.h"
#include "core/or/cpath_build_state_st.h"
#include "core/or/extend_info_st.h"
#include "core/or/relay_msg_st.h"
#include "core/crypto/onion_ntor_v3.h"
#include "core/crypto/onion_crypto.h"
#include "core/or/onion.h"
#include "core/or/circuitlist.h"
#include "core/or/circuitbuild.h"
#include "core/or/circuituse.h"
#include "core/or/relay.h"
#include "feature/payment/payment_origin.h"
#include "feature/payment/payment_initial.h"
#include "feature/payment/payment_resources.h"
#include "feature/payment/payment_workqueue.h"
#include "feature/payment/free_capacity_hooks.h"
#include "feature/control/control_payment.h"
#include "lib/crypt_ops/crypto_util.h"
#include "lib/crypt_ops/crypto_rand.h"
#include "lib/crypt_ops/crypto_digest.h"
#include "lib/encoding/binascii.h"
#include "lib/ctime/di_ops.h"
#include "lib/evloop/timers.h"
#include "lib/time/compat_time.h"
#include <string.h>

#define ORIGIN_TOMBSTONE_MS 60000u

typedef struct payment_origin_operation_t {
  struct payment_origin_operation_t *global_next, *hop_next;
  payment_origin_hop_t *owner;
  protocol_budget_memory_t memory;
  uint8_t id[16], nonce[16], digest[32], allocation[32];
  uint8_t *wire;
  uint64_t period, first_send_ms, deadline_ms, retire_ms;
  payment_origin_kind_t kind;
  payment_origin_phase_t phase;
  uint8_t transmissions, relay_status;
  bool result_seen, allocation_available, operation_held;
} payment_origin_operation_t;

struct payment_origin_hop_t {
  struct origin_circuit_t *circ;
  struct crypt_path_t *hop;
  struct payment_origin_hop_t *next;
  payment_origin_operation_t *operations;
  protocol_budget_memory_t memory;
  payment_profile_policy_t policy;
  uint8_t ids[10][32], terms[32], initial[32], active_allocation[32];
  uint64_t constructed_ms, setup_deadline_ms, hard_deadline_ms;
  uint64_t round_deadline_ms, enforcement_deadline_ms;
  uint64_t observed_ms, elapsed_upper_ms, relay_revision, current_round;
  /* Earliest safe local T0 bound, never moved later by a notification/query. */
  uint64_t schedule_origin_ms;
  uint64_t active_period, last_query_ms;
  /* RENEWED ACTIVE proves the allocation, but does not contain a complete
   * START status clock. Suppress mixed-period observations until that arrives. */
  uint64_t pending_active_period;
  uint8_t state, setup_queries;
  bool ready, confirmed, status_seen, failed, query_seen, closed;
  bool schedule_origin_seen;
};

static payment_origin_hop_t *origin_hops;
static payment_origin_operation_t *origin_operations;
static uint32_t origin_operation_count;
static tor_timer_t *origin_timer;
static protocol_budget_memory_t origin_timer_memory;
/* Local observation wait candidate, not a relay timing guarantee. */
static uint32_t query_timeout_ms = 7000;
static bool origin_enabled;
static bool origin_timer_dispatching;
static void schedule_origin_timer(uint64_t now_ms);

static uint64_t
remaining_ms(uint64_t deadline, uint64_t now_ms)
{
  return deadline > now_ms ? deadline-now_ms : 0;
}

static uint64_t
saturating_add(uint64_t a, uint64_t b)
{
  return a > UINT64_MAX-b ? UINT64_MAX : a+b;
}

static bool
zero(const uint8_t *p, size_t n)
{
  uint8_t v = 0;
  for (size_t i = 0; i < n; ++i) v |= p[i];
  return !v;
}

static void
changed(payment_origin_hop_t *h, const char *kind)
{
  if (h->circ && !h->closed)
    control_payment_origin_changed(h->circ, kind);
}

static payment_origin_hop_t *
get_hop(const origin_circuit_t *circ, uint16_t index)
{
  if (!circ || circ->base_.marked_for_close || !index || index > 16)
    return NULL;
  crypt_path_t *hop = circ->cpath;
  if (!hop) return NULL;
  for (uint16_t i = 1; i < index; ++i) {
    hop = hop->next;
    if (!hop || hop == circ->cpath) return NULL;
  }
  return hop->payment_profile;
}

static payment_origin_operation_t *
find_operation(const payment_origin_hop_t *h, const uint8_t id[16])
{
  for (payment_origin_operation_t *op = h->operations; op; op = op->hop_next)
    if (tor_memeq(op->id, id, 16)) return op;
  return NULL;
}

static payment_origin_operation_t *
find_kind(const payment_origin_hop_t *h, payment_origin_kind_t kind,
          uint64_t period)
{
  for (payment_origin_operation_t *op = h->operations; op; op = op->hop_next)
    if (op->kind == kind && op->period == period) return op;
  return NULL;
}

static bool
pending(const payment_origin_operation_t *op)
{
  return op->phase == PAYMENT_ORIGIN_QUEUED ||
         op->phase == PAYMENT_ORIGIN_SENT;
}

static void
fail_profile(payment_origin_hop_t *h)
{
  if (h->failed) return;
  h->failed = true;
  for (payment_origin_operation_t *op = h->operations; op; op = op->hop_next)
    if (pending(op)) op->phase = PAYMENT_ORIGIN_UNCERTAIN;
  changed(h, "EXPIRED");
}


payment_origin_result_t
payment_origin_pin(origin_circuit_t *circ, crypt_path_t *hop,
                   const char *payload, size_t payload_len, uint64_t now_ms)
{
  if (!circ || !hop || circ->base_.marked_for_close) return PAYMENT_ORIGIN_CLOSED;
  if (circ->payment_owned_construction &&
      now_ms >= circ->payment_construction_deadline_ms) return PAYMENT_ORIGIN_EXPIRED;
  if (circ->payment_base_only) return PAYMENT_ORIGIN_UNSUPPORTED;
  if (hop->payment_profile || hop->payment_keys) return PAYMENT_ORIGIN_CONFLICT;
  bool member = false;
  crypt_path_t *path = circ->cpath;
  unsigned hops = 0;
  if (path) do {
    if (path == hop) member = true;
    ++hops; path = path->next;
  } while (path && path != circ->cpath && hops <= 16);
  if (!member || !path || hops > 16) return PAYMENT_ORIGIN_INVALID;
  /* The constructor sets this explicit local gate only for a selected paid
   * profile. A descriptor advertisement alone never enables it. */
  if (!hop->payment_export_requested || !hop->extend_info ||
      !hop->extend_info->supports_ntor_v3 || !hop->extend_info->payment_free_v1 ||
      !hop->extend_info->payment_start_v1)
    return PAYMENT_ORIGIN_UNSUPPORTED;
  payment_profile_policy_t policy;
  payment_initial_material_t material={0};
  if (payment_profile_policy_decode(&policy, hop->extend_info->payment_profile_terms,
                                    PAYMENT_PROFILE_TERMS_LEN) ||
      payment_initial_parse(&material,(const uint8_t *)payload,payload_len) < 0 ||
      (policy.initial_handshake_fee_msat && zero(material.fee_hash, 32)) ||
      now_ms > UINT64_MAX-policy.setup_timeout_ms ||
      now_ms+policy.setup_timeout_ms > UINT64_MAX-policy.max_age_ms)
    return PAYMENT_ORIGIN_INVALID;
  protocol_budget_memory_t memory = {0};
  if (payment_resources_reserve(&memory, sizeof(payment_origin_hop_t)) !=
      PROTOCOL_BUDGET_OK) return PAYMENT_ORIGIN_CAPACITY;
  if (!origin_timer_memory.active &&
      payment_resources_reserve(&origin_timer_memory,
          timer_memory_cost()+sizeof(origin_timer_memory)) !=
      PROTOCOL_BUDGET_OK) {
    payment_resources_release(&memory);
    return PAYMENT_ORIGIN_CAPACITY;
  }
  control_payment_init();
  if (control_payment_register(TO_CIRCUIT(circ),CONTROL_PAYMENT_ORIGIN,
                                (uint16_t)hops,false) < 0) {
    payment_resources_release(&memory);
    if (!origin_hops && !origin_operations)
      payment_resources_release(&origin_timer_memory);
    return PAYMENT_ORIGIN_CAPACITY;
  }
  payment_origin_hop_t *h = tor_malloc_zero(sizeof(*h));
  h->memory = memory;
  h->circ = circ; h->hop = hop; h->policy = policy;
  h->constructed_ms = now_ms;
  h->setup_deadline_ms = now_ms+policy.setup_timeout_ms;
  if (circ->payment_owned_construction &&
      circ->payment_construction_deadline_ms < h->setup_deadline_ms)
    h->setup_deadline_ms = circ->payment_construction_deadline_ms;
  h->hard_deadline_ms = h->setup_deadline_ms+policy.max_age_ms;
  memcpy(h->ids, material.ids, sizeof(h->ids));
  payment_initial_clear(&material);
  payment_profile_terms_digest(h->terms, &policy);
  h->next = origin_hops; origin_hops = h;
  hop->payment_profile = h;
  schedule_origin_timer(now_ms);
  return PAYMENT_ORIGIN_OK;
}

payment_origin_result_t
payment_origin_handshake_complete(origin_circuit_t *circ, crypt_path_t *hop,
                                   uint64_t now_ms)
{
  payment_origin_hop_t *h = hop ? hop->payment_profile : NULL;
  if (!h || h->circ != circ || h->closed || !hop->payment_export_requested ||
      !hop->payment_keys || now_ms >= h->setup_deadline_ms)
    return PAYMENT_ORIGIN_UNCONFIRMED;
  if (h->ready) return PAYMENT_ORIGIN_OK;
  payment_profile_initial_digest(h->initial, hop->payment_keys->binding,
                                  h->terms, h->ids);
  memcpy(h->active_allocation, h->initial, 32);
  h->ready = true;
  control_payment_init();
  if (control_payment_register(TO_CIRCUIT(circ), CONTROL_PAYMENT_ORIGIN,
                                (uint16_t)circuit_get_cpath_len(circ), true) < 0) {
    fail_profile(h);
    return PAYMENT_ORIGIN_CAPACITY;
  }
  return PAYMENT_ORIGIN_OK;
}

int
payment_origin_configure_enabled(bool enabled)
{
  if (enabled==origin_enabled) return 0;
  if (origin_hops || origin_operations ||
      payment_resources_free()->live_circuits) return -1;
  origin_enabled = enabled;
  return 0;
}

/* Checked graph accounting precedes the first public-key operation. The
 * existing constructor calloc capacity must be supplied by its allocator;
 * strlen alone cannot recover it. Opaque native crypto has a separate fixed
 * conservative candidate allowance, in addition to every known object below. */
static int
construction_add(size_t *cost, size_t bytes)
{
  if (bytes > SIZE_MAX - *cost) return -1;
  *cost += bytes;
  return 0;
}

static int
construction_string(size_t *cost, const char *value, size_t maximum)
{
  if (!value) return 0;
  size_t length = strnlen(value, maximum + 1);
  return length > maximum ? -1 : construction_add(cost, length + 1);
}

int
payment_origin_construction_cost(const origin_circuit_t *circ, size_t *cost_out)
{
  if (!circ || !circ->cpath || !cost_out) return -1;
  size_t cost = sizeof(*circ) + sizeof(cpath_build_state_t) +
    3 * sizeof(extend_info_t) + sizeof(create_cell_t);
  /* Reserves chosen_exit, n_hop and one transient extend_info replacement,
   * whether already allocated or needed later by this immutable constructor. */
  if (circ->payhashes) {
    size_t length = strnlen(circ->payhashes, PAYMENT_ORIGIN_CONSTRUCTION_PAYHASH_BYTES + 1);
    if (length > PAYMENT_ORIGIN_CONSTRUCTION_PAYHASH_BYTES || circ->payment_payhash_capacity <= length ||
        circ->payment_payhash_capacity > 16 * (16 * 1024 + 1) + 1 ||
        construction_add(&cost, circ->payment_payhash_capacity) < 0)
      return -1;
  } else if (circ->payment_payhash_capacity) return -1;
  if (circ->relay_payments) {
    const smartlist_t *items = circ->relay_payments;
    if (items->num_used < 0 || items->num_used > 16 ||
        items->capacity < items->num_used || items->capacity > 32 ||
        (items->capacity && !items->list) ||
        construction_add(&cost, sizeof(*items) +
                         (size_t)items->capacity * sizeof(void *)) < 0)
      return -1;
    SMARTLIST_FOREACH_BEGIN(items, const relay_payment_item_t *, item) {
      if (!item || construction_add(&cost, sizeof(*item)) < 0 ||
          construction_string(&cost, item->fingerprint,
                              MAX_HEX_NICKNAME_LEN) < 0 ||
          construction_string(&cost, item->handshake_payment_hash, 64) < 0 ||
          construction_string(&cost, item->handshake_preimage, 64) < 0 ||
          construction_string(&cost, item->payhashes, 640) < 0 ||
          construction_string(&cost, item->wire_format, 781) < 0)
        return -1;
    } SMARTLIST_FOREACH_END(item);
  }
  unsigned hops = 0;
  const crypt_path_t *hop = circ->cpath;
  do {
    if (!hop || !hop->extend_info || ++hops > 16 ||
        construction_add(&cost, sizeof(*hop) + sizeof(extend_info_t) +
          sizeof(payment_profile_keys_t) + onion_ntor3_client_state_memory_cost() +
          MAX_CREATE_LEN + PAYMENT_ORIGIN_NATIVE_CRYPTO_RESERVE) < 0)
      return -1;
    hop = hop->next;
  } while (hop != circ->cpath);
  *cost_out = cost;
  return 0;
}

int
payment_origin_reserve_construction(origin_circuit_t *circ)
{
  size_t cost;
  if (payment_origin_construction_cost(circ, &cost) < 0) return -1;
  unsigned hops = 1;
  for (const crypt_path_t *hop = circ->cpath->next; hop != circ->cpath;
       hop = hop->next) ++hops;
  if (circ->payment_construction_memory.active)
    return hops == circ->payment_construction_hops &&
      cost <= circ->payment_construction_memory.allocation_bytes ? 0 : -1;
  if (payment_resources_reserve(&circ->payment_construction_memory, cost) !=
      PROTOCOL_BUDGET_OK) return -1;
  circ->payment_construction_hops = (uint16_t)hops;
  circ->payment_construction_deadline_ms =
    saturating_add(monotime_absolute_msec(), FREE_CAPACITY_LIFETIME_MS);
  return 0;
}

bool
payment_origin_build_deadline(const origin_circuit_t *circ, uint64_t *deadline)
{
  if (!circ || !circ->payment_owned_construction) return false;
  if (deadline) *deadline = circ->payment_construction_deadline_ms;
  return true;
}

int
payment_origin_prepare_owned_construction(origin_circuit_t *circ)
{
  if (!origin_enabled) return 0;
  if (!circ || !circ->cpath || !circ->payhashes ||
      !circ->any_hop_from_controller || circ->payment_base_only ||
      circ->payment_internal_free) return -1;
  if (circ->payment_owned_construction) return 0;
  uint64_t setup_ms = UINT64_MAX;
  const crypt_path_t *hop = circ->cpath;
  unsigned count = 0;
  do {
    payment_profile_policy_t policy;
    const extend_info_t *info = hop->extend_info;
    if (++count > 16 || !info || !info->supports_ntor_v3 ||
        !info->payment_free_v1 || !info->payment_start_v1 ||
        payment_profile_policy_decode(&policy, info->payment_profile_terms,
                                       PAYMENT_PROFILE_TERMS_LEN)) return -1;
    if (policy.setup_timeout_ms < setup_ms) setup_ms = policy.setup_timeout_ms;
    hop = hop->next;
  } while (hop && hop != circ->cpath);
  if (!hop || payment_origin_reserve_construction(circ) < 0) return -1;
  uint64_t began = circ->payment_construction_deadline_ms-
                   FREE_CAPACITY_LIFETIME_MS;
  uint64_t deadline = saturating_add(began, setup_ms);
  if (deadline < circ->payment_construction_deadline_ms)
    circ->payment_construction_deadline_ms = deadline;
  circ->payment_owned_construction = true;
  return 0;
}

static uint64_t
origin_work_deadline(const origin_circuit_t *circ, const crypt_path_t *hop)
{
  uint64_t deadline = circ->payment_construction_deadline_ms;
  uint64_t wait = saturating_add(monotime_absolute_msec(),
                                 payment_resources_protocol()->limits.max_wait_ms);
  if (hop && hop->payment_profile &&
      hop->payment_profile->setup_deadline_ms < deadline)
    deadline = hop->payment_profile->setup_deadline_ms;
  return MIN(deadline, wait);
}

typedef struct base_generation_t {
  uint8_t *raw;
  const uint8_t (*prior_ids)[10][32];
  unsigned hop;
} base_generation_t;

static int
generate_base_step(void *arg)
{
  base_generation_t *step = arg;
  uint8_t *raw = step->raw;
  crypto_rand((char *)raw + 32, 352);
  if (!payment_profile_ids_valid((const uint8_t (*)[32])(raw + 64))) return 0;
  for (unsigned prior = 0; prior < step->hop; ++prior)
    for (unsigned a = 0; a < 10; ++a)
      for (unsigned b = 0; b < 10; ++b)
        if (tor_memeq(step->prior_ids[prior][a], raw + 64 + 32*b, 32))
          return 0;
  return crypto_digest256((char *)raw, (const char *)raw + 32, 32,
                           DIGEST_SHA256) < 0 ? -1 : 1;
}

static int
prepare_base_material(origin_circuit_t *circ)
{
  if (!circ || circ->base_.marked_for_close || !circ->build_state ||
      !circ->cpath) return -1;
  if (circ->payment_base_only)
    return payment_origin_reserve_construction(circ);
  if (circ->payhashes || circ->relay_payments ||
      circ->payment_construction_memory.active) return -1;
  const crypt_path_t *hop = circ->cpath;
  unsigned hops = 0;
  do {
    if (!hop || !hop->extend_info || ++hops > 16 ||
        hop->state != CPATH_STATE_CLOSED ||
        !hop->extend_info->payment_free_v1 ||
        !hop->extend_info->supports_ntor_v3) return -1;
    hop = hop->next;
  } while (hop != circ->cpath);
  size_t cost, capacity = hops * 768u + 1u;
  if (payment_origin_construction_cost(circ, &cost) < 0 ||
      construction_add(&cost, capacity) < 0 ||
      payment_resources_reserve(&circ->payment_construction_memory, cost) !=
        PROTOCOL_BUDGET_OK) return -1;
  circ->payment_construction_hops = (uint16_t)hops;
  circ->payment_construction_deadline_ms =
    saturating_add(monotime_absolute_msec(), FREE_CAPACITY_LIFETIME_MS);
  circ->payhashes = tor_malloc_zero(capacity);
  circ->payment_payhash_capacity = capacity;
  uint8_t raw[384] = {0}, ids[16][10][32] = {{{0}}};
  for (unsigned i = 0; i < hops; ++i) {
    int generated = 0;
    base_generation_t step = { raw, ids, i };
    for (unsigned attempt = 0; attempt < 4 && !generated; ++attempt) {
      if (!payment_work_run_sync(sizeof(raw)+sizeof(ids)+sizeof(step),
            origin_work_deadline(circ, NULL), generate_base_step, &step,
            &generated)) generated = -1;
    }
    if (generated != 1) {
      memwipe(raw, 0, sizeof(raw)); memwipe(ids, 0, sizeof(ids));
      /* No onionskin has been published. Close caller; retain the graph lease
       * until its actual free, including this partially allocated backing. */
      return -1;
    }
    memcpy(ids[i], raw + 64, sizeof(ids[i]));
    base16_encode(circ->payhashes + i*768u, capacity - i*768u,
                   (const char *)raw, sizeof(raw));
  }
  tor_strlower(circ->payhashes);
  memwipe(raw, 0, sizeof(raw)); memwipe(ids, 0, sizeof(ids));
  circ->payment_base_only = true;
  return 0;
}

typedef struct origin_create_t {
  crypt_path_t *hop;
  int type;
  uint8_t *out;
  size_t capacity;
  const char *payload;
} origin_create_t;

static int
create_origin_step(void *arg)
{
  origin_create_t *create = arg;
  return onion_skin_create(create->type, create->hop->extend_info,
             &create->hop->handshake_state, create->out, create->capacity,
             create->payload, create->hop->payment_export_requested);
}

int
payment_origin_create_onionskin(origin_circuit_t *circ, crypt_path_t *hop,
                                 int type, uint8_t *out, size_t capacity,
                                 const char *payload)
{
  if (!circ || !hop || !hop->extend_info || !out || !capacity ||
      capacity > MAX_CREATE_LEN || circ->base_.marked_for_close) return -1;
  origin_create_t create = {hop, type, out, capacity, payload};
  if (!origin_enabled) return create_origin_step(&create);
  if (hop->handshake_state.tag) return -1;
  /* The directory/bootstrap exception shares these limits too. Persistent
   * handshake backing remains charged by the graph lease after this job ends. */
  if (payment_origin_reserve_construction(circ) < 0)
    return PAYMENT_ORIGIN_WORK_REFUSED;
  int result;
  size_t retained = sizeof(create)+capacity+
    onion_ntor3_client_state_memory_cost()+PAYMENT_ORIGIN_NATIVE_CRYPTO_RESERVE;
  if (!payment_work_run_sync(retained, origin_work_deadline(circ, hop),
                              create_origin_step, &create, &result)) {
    /* An executed but late result must never be transmitted/installed. */
    if (hop->handshake_state.tag) {
      onion_handshake_state_release(&hop->handshake_state);
      memset(&hop->handshake_state, 0, sizeof(hop->handshake_state));
      memwipe(out, 0, capacity);
    }
    return PAYMENT_ORIGIN_WORK_REFUSED;
  }
  return result;
}

typedef struct origin_finish_t {
  crypt_path_t *hop;
  const uint8_t *reply;
  size_t reply_len;
  uint8_t *keys;
  size_t *keylen;
  uint8_t *nonce;
  circuit_params_t *params;
  const char **msg;
  payment_profile_export_t *payment;
} origin_finish_t;

static int
finish_origin_step(void *arg)
{
  origin_finish_t *finish = arg;
  return onion_skin_client_handshake(finish->hop->handshake_state.tag,
      &finish->hop->handshake_state, finish->reply, finish->reply_len,
      finish->keys, finish->keylen, finish->nonce, finish->params,
      finish->msg, finish->payment);
}

int
payment_origin_finish_onionskin(origin_circuit_t *circ, crypt_path_t *hop,
    const uint8_t *reply, size_t reply_len, uint8_t *keys, size_t *keylen,
    uint8_t *nonce, circuit_params_t *params, const char **msg,
    payment_profile_export_t *payment)
{
  if (!circ || !hop || !reply || !keys || !keylen || !nonce || !params ||
      !msg || !payment || reply_len > MAX_CREATED_LEN ||
      *keylen > MAX_RELAY_KEY_MATERIAL_LEN || circ->base_.marked_for_close)
    return -1;
  origin_finish_t finish = {hop, reply, reply_len, keys, keylen, nonce,
                            params, msg, payment};
  if (!origin_enabled) return finish_origin_step(&finish);
  size_t key_capacity = *keylen;
  size_t retained = sizeof(finish)+reply_len+key_capacity+DIGEST_LEN+
    sizeof(*params)+sizeof(*payment)+PAYMENT_ORIGIN_NATIVE_CRYPTO_RESERVE;
  int result;
  if (!circ->payment_construction_memory.active ||
      !payment_work_run_sync(retained, origin_work_deadline(circ, hop),
                              finish_origin_step, &finish, &result)) {
    memwipe(keys, 0, key_capacity); *keylen = 0;
    memwipe(nonce, 0, DIGEST_LEN); memset(params, 0, sizeof(*params));
    payment_profile_export_clear(payment);
    *msg = "Origin setup resource limit";
    return PAYMENT_ORIGIN_WORK_REFUSED;
  }
  return result;
}

int
payment_origin_prepare_base(origin_circuit_t *circ)
{
  if (!origin_enabled) return 0;
  if (!circ || !circ->build_state || circ->base_.marked_for_close) return -1;
  if (circ->payment_base_only) return prepare_base_material(circ);
  /* Explicit paid constructors retain their immutable accepted material. A
   * failed/committed paid path is never converted into a free circuit. */
  if (circ->payhashes || circ->relay_payments) return 0;
  /* Bootstrap precedes full authenticated descriptor availability. This narrow
   * existing directory-only exception cannot carry application streams. */
  if (circ->base_.purpose == CIRCUIT_PURPOSE_C_GENERAL &&
      circ->build_state->onehop_tunnel) return 0;
  return prepare_base_material(circ);
}

int
payment_origin_prepare_reachability(origin_circuit_t *circ)
{
  if (!origin_enabled) return 0;
  if (!circ || circ->base_.purpose != CIRCUIT_PURPOSE_TESTING ||
      !circ->build_state || !circ->build_state->is_internal ||
      circ->build_state->onehop_tunnel) return -1;
  if (prepare_base_material(circ) < 0) return -1;
  circ->payment_internal_free = true;
  return 0;
}

int
payment_origin_prepare_handshake(origin_circuit_t *circ, crypt_path_t *hop,
                                  const char *payload, uint64_t now_ms)
{
  if (!origin_enabled) return 0;
  if (!circ || !hop || !hop->extend_info || !circ->cpath) return -1;
  if (circ->payment_internal_free &&
      (circ->base_.purpose != CIRCUIT_PURPOSE_TESTING || !circ->build_state ||
       !circ->build_state->is_internal)) return -1;
  if (!payload) {
    /* Directory bootstrap uses a purpose-limited one-hop tunnel before full
     * signed descriptors or daemon-owned foundation circuits are available. */
    if (circ->base_.purpose != CIRCUIT_PURPOSE_C_GENERAL || !circ->build_state ||
        !circ->build_state->onehop_tunnel) return -1;
    if (!circ->base_.free_capacity &&
        free_capacity_circuit_prepare_channel(TO_CIRCUIT(circ),
                                               circ->base_.n_chan) < 0)
      return -1;
    return 0;
  }
  bool selected=false, supported=true, any_paid=false, all_paid=true;
  unsigned hops=0;
  crypt_path_t *p=circ->cpath;
  do {
    if (!p->extend_info) return -1;
    selected|=p->extend_info->payment_free_v1 || p->extend_info->payment_start_v1;
    supported&=p->extend_info->payment_free_v1 && p->extend_info->supports_ntor_v3;
    any_paid|=p->extend_info->payment_start_v1;
    all_paid&=p->extend_info->payment_start_v1;
    p=p->next;
  } while (p && p!=circ->cpath && ++hops<16);
  if (!selected) return -1; /* Explicit selection never falls back to legacy. */
  if (!supported || p!=circ->cpath || hops>=16 ||
      (!circ->payment_base_only && any_paid && !all_paid))
    return -1;
  if (!payload) return -1;
  payment_initial_material_t material={0};
  if (payment_initial_parse(&material,(const uint8_t *)payload,strlen(payload))<0)
    return -1;
  payment_initial_clear(&material);
  if (payment_origin_reserve_construction(circ) < 0) return -1;
  if (!circ->base_.free_capacity &&
      free_capacity_circuit_prepare_channel(TO_CIRCUIT(circ),circ->base_.n_chan)<0)
    return -1;
  hop->payment_export_requested = true;
  if (!hop->extend_info->payment_start_v1 || circ->payment_base_only) {
    control_payment_init();
    if (control_payment_register(TO_CIRCUIT(circ),CONTROL_PAYMENT_ORIGIN,
                             (uint16_t)circuit_get_cpath_len(circ),false)<0) {
      hop->payment_export_requested=false;
      return -1;
    }
    return 0;
  }
  payment_origin_result_t r = payment_origin_pin(circ,hop,payload,strlen(payload),
                                                 now_ms);
  if (r != PAYMENT_ORIGIN_OK) {
    hop->payment_export_requested = false;
    return -1;
  }
  return 0;
}

int
payment_origin_resource_complete(origin_circuit_t *circ, crypt_path_t *hop,
                                  bool admitted, uint64_t now_ms)
{
  if (!circ || !hop || admitted!=hop->payment_export_requested) goto fail;
  if (!admitted) {
    if (circ->base_.free_capacity &&
        free_capacity_circuit_confirm_bootstrap(TO_CIRCUIT(circ)) < 0)
      goto fail;
    return 0;
  }
  if (!hop->payment_keys) goto fail;
  if (free_capacity_circuit_confirm(TO_CIRCUIT(circ))<0) goto fail;
  if (hop->payment_profile) {
    if (payment_origin_handshake_complete(circ,hop,now_ms)!=PAYMENT_ORIGIN_OK)
      goto fail;
  } else if (control_payment_register(TO_CIRCUIT(circ),CONTROL_PAYMENT_ORIGIN,
                          (uint16_t)circuit_get_cpath_len(circ),true)<0)
    goto fail;
  return 0;
 fail:
  if (hop) {
    payment_profile_keys_free(hop->payment_keys);
    hop->payment_export_requested=false;
  }
  return -1;
}

static int
send_operation(payment_origin_operation_t *op, uint64_t now_ms)
{
  payment_origin_hop_t *h = op->owner;
  if (!h || h->closed || h->failed || !op->wire ||
      !h->circ || h->circ->base_.marked_for_close || now_ms >= op->deadline_ms)
    return -1;
  uint8_t command = op->kind == PAYMENT_ORIGIN_RENEW ? PAYMENT_PROFILE_RENEW :
    op->kind == PAYMENT_ORIGIN_COMMIT ? PAYMENT_PROFILE_COMMIT :
                                      PAYMENT_PROFILE_START_STATUS;
  if (!op->transmissions) op->first_send_ms = now_ms;
  ++op->transmissions;
  op->phase = PAYMENT_ORIGIN_SENT;
  int r = relay_send_command_from_edge(0, TO_CIRCUIT(h->circ), command,
                (const char *)op->wire, PAYMENT_PROFILE_WIRE_LEN, h->hop);
  if (r < 0) op->phase = PAYMENT_ORIGIN_UNCERTAIN;
  changed(h, "REGISTERED");
  return r;
}

static payment_origin_result_t
queue_operation(payment_origin_hop_t *h, payment_origin_kind_t kind,
                const uint8_t id[16], const uint8_t nonce[16], uint64_t period,
                const payment_profile_message_t *request, uint64_t deadline,
                uint64_t now_ms)
{
  if (!id || !nonce || zero(id, 16) || zero(nonce, 16))
    return PAYMENT_ORIGIN_INVALID;
  uint8_t wire[PAYMENT_PROFILE_WIRE_LEN];
  const uint8_t *key = kind == PAYMENT_ORIGIN_RENEW ?
    h->hop->payment_keys->renew_request : h->hop->payment_keys->start_request;
  if (payment_profile_encode(wire, sizeof(wire), request, key,
                              h->hop->payment_keys->binding))
    return PAYMENT_ORIGIN_INVALID;
  payment_origin_operation_t *existing = find_operation(h, id);
  if (existing)
    return existing->kind == kind && existing->wire &&
      tor_memeq(existing->wire, wire, sizeof(wire)) ? PAYMENT_ORIGIN_OK :
                                                     PAYMENT_ORIGIN_CONFLICT;
  if (kind != PAYMENT_ORIGIN_QUERY && find_kind(h, kind, period))
    return PAYMENT_ORIGIN_CONFLICT;
  for (payment_origin_operation_t *op = h->operations; op; op = op->hop_next) {
    if (tor_memeq(op->nonce, nonce, 16)) return PAYMENT_ORIGIN_CONFLICT;
    if (kind == PAYMENT_ORIGIN_QUERY && op->kind == PAYMENT_ORIGIN_QUERY &&
        pending(op)) return PAYMENT_ORIGIN_CAPACITY;
  }
  if (h->failed || now_ms >= deadline) return PAYMENT_ORIGIN_EXPIRED;

  if (kind == PAYMENT_ORIGIN_QUERY &&
      ((h->query_seen && (now_ms < h->last_query_ms ||
                          now_ms-h->last_query_ms < 1000)) ||
       (!h->status_seen && h->setup_queries >= 16))) return PAYMENT_ORIGIN_CAPACITY;
  protocol_budget_memory_t memory = {0};
  bool held = false;
  if (!payment_resources_operation_reserve(&held)) return PAYMENT_ORIGIN_CAPACITY;
  if (payment_resources_reserve(&memory,
         sizeof(payment_origin_operation_t)+sizeof(wire)) != PROTOCOL_BUDGET_OK) {
    payment_resources_operation_release(&held);
    return PAYMENT_ORIGIN_CAPACITY;
  }
  payment_origin_operation_t *op = tor_malloc_zero(sizeof(*op));
  op->memory = memory; op->operation_held = held;
  op->wire = tor_memdup(wire, sizeof(wire));
  op->owner = h; op->kind = kind; op->period = period;
  op->deadline_ms = deadline; op->phase = PAYMENT_ORIGIN_QUEUED;
  if (kind == PAYMENT_ORIGIN_QUERY) {
    uint64_t response_deadline = saturating_add(now_ms, query_timeout_ms);
    if (response_deadline < op->deadline_ms) op->deadline_ms = response_deadline;
  }
  memcpy(op->id, id, 16); memcpy(op->nonce, nonce, 16);
  payment_profile_request_digest(op->digest, request->command, wire,sizeof(wire));
  if (kind == PAYMENT_ORIGIN_RENEW) {
    payment_profile_allocation_digest(op->allocation, h->hop->payment_keys->binding,
                                       wire, sizeof(wire));
  }
  op->hop_next = h->operations; h->operations = op;
  op->global_next = origin_operations; origin_operations = op;
  ++origin_operation_count;
  if (kind == PAYMENT_ORIGIN_QUERY) {
    h->query_seen = true; h->last_query_ms = now_ms;
    if (!h->status_seen) ++h->setup_queries;
  }
  send_operation(op, now_ms);
  schedule_origin_timer(now_ms);
  return PAYMENT_ORIGIN_OK;
}

static payment_origin_result_t
usable(payment_origin_hop_t *h)
{
  if (!h || h->closed) return PAYMENT_ORIGIN_CLOSED;
  if (!h->ready) return PAYMENT_ORIGIN_UNCONFIRMED;
  return PAYMENT_ORIGIN_OK;
}

payment_origin_result_t
payment_origin_initial_prepare(origin_circuit_t *circ, uint16_t index,
    const uint8_t operation[16], const uint8_t nonce[16],
    const uint8_t policy[55], uint64_t now_ms)
{
  payment_origin_hop_t *h = get_hop(circ, index);
  payment_origin_result_t r = usable(h);
  if (r) return r;
  uint8_t pinned[PAYMENT_PROFILE_TERMS_LEN];
  payment_profile_policy_encode(pinned, sizeof(pinned), &h->policy);
  if (!policy || tor_memneq(pinned, policy, sizeof(pinned)))
    return PAYMENT_ORIGIN_BAD_SEQUENCE;
  payment_profile_message_t m = { .command = PAYMENT_PROFILE_COMMIT };
  m.u.commit.policy = h->policy;
  if (!nonce) return PAYMENT_ORIGIN_INVALID;
  memcpy(m.u.commit.nonce, nonce, 16);
  memcpy(m.u.commit.allocation, h->initial, 32);
  return queue_operation(h, PAYMENT_ORIGIN_COMMIT, operation, nonce, 0, &m,
                          h->setup_deadline_ms, now_ms);
}

static payment_origin_result_t
initial_status(origin_circuit_t *circ, uint16_t index,
    const uint8_t operation[16], const uint8_t nonce[16], bool query,
    uint64_t now_ms)
{
  payment_origin_hop_t *h = get_hop(circ, index);
  payment_origin_result_t r = usable(h);
  if (r) return r;
  if (!h->confirmed) return PAYMENT_ORIGIN_UNCONFIRMED;
  if (!nonce) return PAYMENT_ORIGIN_INVALID;
  payment_profile_message_t m = { .command = PAYMENT_PROFILE_START_STATUS };
  m.u.start.action = query ? 1 : 0; m.u.start.round = query ? 0 : 1;
  memcpy(m.u.start.nonce, nonce, 16);
  memcpy(m.u.start.terms, h->terms, 32);
  memcpy(m.u.start.allocation, h->initial, 32);
  return queue_operation(h, query ? PAYMENT_ORIGIN_QUERY : PAYMENT_ORIGIN_START,
      operation, nonce, 0, &m, query && h->current_round ? h->hard_deadline_ms :
                                                     h->setup_deadline_ms,
      now_ms);
}

payment_origin_result_t
payment_origin_initial_start(origin_circuit_t *circ, uint16_t index,
    const uint8_t operation[16], const uint8_t nonce[16], uint64_t now_ms)
{
  return initial_status(circ, index, operation, nonce, false, now_ms);
}

payment_origin_result_t
payment_origin_initial_refresh(origin_circuit_t *circ, uint16_t index,
    const uint8_t operation[16], const uint8_t nonce[16], uint64_t now_ms)
{
  return initial_status(circ, index, operation, nonce, true, now_ms);
}

payment_origin_result_t
payment_origin_renew_prepare(origin_circuit_t *circ, uint16_t index,
    const uint8_t operation[16], uint64_t period, uint64_t first_round,
    const uint8_t nonce[16], const uint8_t terms[32], const uint8_t parent[32],
    const uint8_t ids[10][32], uint64_t now_ms)
{
  payment_origin_hop_t *h = get_hop(circ, index);
  payment_origin_result_t r = usable(h);
  if (r) return r;
  if (!nonce || !terms || !parent || !ids) return PAYMENT_ORIGIN_INVALID;
  payment_profile_message_t m = { .command = PAYMENT_PROFILE_RENEW };
  m.u.renew.period = period; m.u.renew.first_round = first_round;
  if (period > UINT64_MAX/(10*PAYMENT_PROFILE_ROUND_MS))
    return PAYMENT_ORIGIN_INVALID;
  m.u.renew.activation_ms = period*10*PAYMENT_PROFILE_ROUND_MS;
  memcpy(m.u.renew.nonce, nonce, 16); memcpy(m.u.renew.terms, terms, 32);
  memcpy(m.u.renew.parent, parent, 32); memcpy(m.u.renew.ids, ids, 320);
  /* Exact operation recovery precedes time/sequence checks; it never sends. */
  payment_origin_operation_t *old = operation ? find_operation(h, operation) : NULL;
  if (!old && (!h->confirmed || !h->status_seen || h->state<3 || h->state>4))
    return PAYMENT_ORIGIN_UNCONFIRMED;
  if (!old && !h->hop->extend_info->payment_renew_v1)
    return PAYMENT_ORIGIN_UNSUPPORTED;
  if (!old && payment_profile_renew_check(&m.u.renew, &h->policy,
              h->active_period+1, h->terms, h->active_allocation))
    return PAYMENT_ORIGIN_BAD_SEQUENCE;
  if (!old) {
    for (size_t i = 0; i < 10; ++i)
      for (size_t j = 0; j < 10; ++j)
        if (tor_memeq(ids[i], h->ids[j], 32)) return PAYMENT_ORIGIN_BAD_SEQUENCE;
    for (payment_origin_operation_t *op = h->operations; op; op = op->hop_next) {
      if (op->kind != PAYMENT_ORIGIN_RENEW || !op->wire) continue;
      payment_profile_message_t previous;
      if (payment_profile_decode(&previous, PAYMENT_PROFILE_RENEW, op->wire,
            PAYMENT_PROFILE_WIRE_LEN, h->hop->payment_keys->renew_request,
            h->hop->payment_keys->binding)) return PAYMENT_ORIGIN_INVALID;
      for (size_t i = 0; i < 10; ++i)
        for (size_t j = 0; j < 10; ++j)
          if (tor_memeq(ids[i], previous.u.renew.ids[j], 32))
            return PAYMENT_ORIGIN_BAD_SEQUENCE;
    }
  }
  uint64_t elapsed = saturating_add(h->elapsed_upper_ms,
                                      remaining_ms(now_ms, h->observed_ms));
  uint64_t admit = m.u.renew.activation_ms-PAYMENT_PROFILE_ROUND_MS;
  uint64_t deadline = saturating_add(now_ms, remaining_ms(admit, elapsed));
  if (h->hard_deadline_ms < deadline) deadline = h->hard_deadline_ms;
  return queue_operation(h, PAYMENT_ORIGIN_RENEW, operation, nonce, period,
                          &m, deadline, now_ms);
}

static void
learn_deadline(uint64_t *old, uint64_t candidate)
{
  if (!*old || candidate < *old) *old = candidate;
}

bool
payment_origin_present(const origin_circuit_t *circ)
{
  if (!circ) return false;
  if (circ->payment_base_only) return true;
  const crypt_path_t *hop=circ->cpath;
  unsigned count=0;
  if (hop) do {
    if (++count>16 || hop->payment_export_requested || hop->payment_profile)
      return true;
    hop=hop->next;
  } while (hop && hop!=circ->cpath);
  return false;
}

bool
payment_origin_data_active(const origin_circuit_t *circ, uint64_t now_ms)
{
  if (!circ || circ->base_.marked_for_close) return false;
  const crypt_path_t *hop=circ->cpath;
  if (!hop) return false;
  unsigned count=0;
  do {
    const payment_origin_hop_t *h=hop->payment_profile;
    if (++count>16 || !h || h->closed || h->failed || !h->confirmed ||
        !h->status_seen || h->pending_active_period || h->state != 3 ||
        now_ms<h->observed_ms ||
        !remaining_ms(h->round_deadline_ms,now_ms) ||
        !remaining_ms(h->enforcement_deadline_ms,now_ms) ||
        !remaining_ms(h->hard_deadline_ms,now_ms)) return false;
    hop=hop->next;
  } while (hop && hop!=circ->cpath);
  return hop!=NULL;
}

bool
payment_origin_streams_ready(const origin_circuit_t *circ, uint64_t now_ms)
{
  if (!circ || circ->base_.marked_for_close || circ->payment_internal_free)
    return false;
  const crypt_path_t *hop=circ->cpath;
  unsigned count=0;
  bool resource_only=free_capacity_circuit_ready(&circ->base_,now_ms);
  if (hop) do {
    if (++count>16) return false;
    if (hop->payment_profile) return payment_origin_data_active(circ,now_ms);
    resource_only&=hop->payment_export_requested && hop->payment_keys &&
                   hop->state==CPATH_STATE_OPEN;
    hop=hop->next;
  } while (hop && hop!=circ->cpath);
  /* A configured paid client may still construct bounded base circuits for
   * protocol work, but user streams must never downgrade onto those circuits
   * after its funded path closes. Enforcement stays in Tor, not UI status. */
  if (origin_enabled && get_options()->ElTorRequirePaidStreams &&
      (circ->base_.purpose == CIRCUIT_PURPOSE_C_GENERAL ||
       circ->base_.purpose == CIRCUIT_PURPOSE_CONFLUX_LINKED ||
       circ->base_.purpose == CIRCUIT_PURPOSE_CONFLUX_UNLINKED))
    return false;
  return !origin_enabled || (count && hop && resource_only);
}

static void
observe_paid_path(origin_circuit_t *circ, uint64_t now_ms)
{
  if (payment_origin_data_active(circ,now_ms)) {
    free_capacity_circuit_paid(TO_CIRCUIT(circ));
    circuit_paid_resume_edge_reading(TO_CIRCUIT(circ));
    if (circ->base_.state==CIRCUIT_STATE_OPEN && circ->base_.n_chan)
      circuit_try_attaching_streams(circ);
  }
}

static uint64_t
reply_deadline(const payment_origin_operation_t *op, uint64_t remaining)
{
  return saturating_add(op->first_send_ms, remaining);
}

static bool
apply_status(payment_origin_hop_t *h, payment_origin_operation_t *op,
             const payment_profile_started_t *r, uint64_t now_ms)
{
  if (tor_memneq(r->terms, h->terms, 32) ||
      tor_memneq(r->allocation, h->initial, 32)) return false;
  /* The immutable START can receive transition notifications for its whole
   * live schedule. Exact/historical replay must not mutate live observations. */
  bool notification = op->kind == PAYMENT_ORIGIN_START &&
                      h->schedule_origin_seen && op->result_seen;
  if (notification && r->revision <= h->relay_revision) {
    return r->revision < h->relay_revision ||
           (r->state == h->state && r->round == h->current_round);
  }
  if (h->status_seen && r->revision < h->relay_revision) {
    op->phase = PAYMENT_ORIGIN_VERIFIED;
    op->relay_status = r->state; op->result_seen = true;
    changed(h,"REGISTERED");
    return true;
  }
  if (h->status_seen && r->revision == h->relay_revision &&
      (r->state != h->state || r->round != h->current_round)) return false;
  if (h->status_seen && r->round < h->current_round) return false;
  if (r->state == 0 || r->state == 7) return false;
  if (r->setup_remaining_ms > h->policy.setup_timeout_ms) return false;
  if (r->state == 3 || r->state == 4) {
    if (r->elapsed_ms >= h->policy.max_age_ms) return false;
    uint64_t hard = h->policy.max_age_ms-r->elapsed_ms;
    uint64_t enforcement = r->state == 3 ?
      r->round_remaining_ms+h->policy.grace_ms :
      remaining_ms(h->policy.grace_ms, r->elapsed_ms%PAYMENT_PROFILE_ROUND_MS);
    if (r->enforcement_remaining_ms > hard ||
        r->enforcement_remaining_ms > enforcement) return false;
    uint64_t period = (r->round-1)/10;
    if (period < h->active_period || period >= h->policy.max_periods)
      return false;
    payment_origin_operation_t *admitted = NULL;
    if (period != h->active_period) {
      admitted = find_kind(h,PAYMENT_ORIGIN_RENEW,period);
      if (!admitted || !admitted->result_seen || !admitted->allocation_available ||
          (admitted->phase != PAYMENT_ORIGIN_ADMITTED &&
           admitted->phase != PAYMENT_ORIGIN_ACTIVE)) return false;
    }
    uint64_t round_end, enforcement_end, hard_end;
    if (notification) {
      if (now_ms < h->schedule_origin_ms ||
          r->elapsed_ms > now_ms-h->schedule_origin_ms ||
          r->round > UINT64_MAX/PAYMENT_PROFILE_ROUND_MS) return false;
      /* The old START has no fresh RTT. Advance only the authenticated round
       * on the original schedule; never treat delivery time as a new T0. */
      round_end = saturating_add(h->schedule_origin_ms,
                                r->round*PAYMENT_PROFILE_ROUND_MS);
      enforcement_end = r->state == 3 ? round_end :
        round_end-PAYMENT_PROFILE_ROUND_MS;
      enforcement_end = saturating_add(enforcement_end,h->policy.grace_ms);
      hard_end = saturating_add(h->schedule_origin_ms,h->policy.max_age_ms);
      if (hard_end < enforcement_end) enforcement_end = hard_end;
      uint64_t reported = saturating_add(now_ms,r->enforcement_remaining_ms);
      if (reported < enforcement_end) enforcement_end = reported;
    } else {
      uint64_t candidate = remaining_ms(op->first_send_ms,r->elapsed_ms);
      if (!h->schedule_origin_seen || candidate < h->schedule_origin_ms)
        h->schedule_origin_ms = candidate;
      h->schedule_origin_seen = true;
      round_end = reply_deadline(op,r->round_remaining_ms);
      enforcement_end = reply_deadline(op,r->enforcement_remaining_ms);
      hard_end = reply_deadline(op,hard);
    }
    uint64_t retained_hard = h->hard_deadline_ms < hard_end ?
                             h->hard_deadline_ms : hard_end;
    uint64_t reported_round = saturating_add(now_ms,r->round_remaining_ms);
    if (reported_round < round_end) round_end = reported_round;
    if (retained_hard < round_end) round_end = retained_hard;
    if (retained_hard < enforcement_end) enforcement_end = retained_hard;
    /* Publish a new allocation only after all authenticated clock checks. */
    if (admitted) {
      h->active_period = period;
      memcpy(h->active_allocation, admitted->allocation, 32);
      admitted->phase = PAYMENT_ORIGIN_ACTIVE;
    }
    if (!h->status_seen || r->round != h->current_round) {
      h->round_deadline_ms = round_end;
      h->enforcement_deadline_ms = enforcement_end;
    } else {
      learn_deadline(&h->round_deadline_ms,round_end);
      if (h->state == 4 && r->state == 3)
        h->enforcement_deadline_ms=enforcement_end;
      else learn_deadline(&h->enforcement_deadline_ms,enforcement_end);
    }
    learn_deadline(&h->hard_deadline_ms,hard_end);
  } else if ((h->status_seen && h->current_round && r->state < 3) ||
             (h->status_seen && h->state >= 5 && r->state < 5)) return false;
  if (r->state < 3)
    learn_deadline(&h->setup_deadline_ms,
                    reply_deadline(op,r->setup_remaining_ms));
  uint64_t upper = notification ?
      now_ms-h->schedule_origin_ms :
      saturating_add(r->elapsed_ms, now_ms-op->first_send_ms);
  if (h->status_seen && h->current_round) {
    uint64_t previous = saturating_add(h->elapsed_upper_ms,
                                       now_ms-h->observed_ms);
    if (previous > upper) upper = previous;
  }
  h->elapsed_upper_ms = r->round ? upper : 0;
  h->observed_ms = now_ms; h->current_round = r->round;
  h->relay_revision = r->revision; h->status_seen = true; h->state = r->state;
  op->phase = PAYMENT_ORIGIN_VERIFIED;
  op->relay_status = r->state; op->result_seen = true;
  if ((r->round && (r->round-1)/10>=h->pending_active_period) ||
      r->state==5 || r->state==6)
    h->pending_active_period=0;
  if (r->state == 5 || r->state == 6) fail_profile(h);
  else {
    observe_paid_path(h->circ,now_ms);
    changed(h, r->state == 3 ? "ROUND_ACTIVE" :
                    r->state == 4 ? "GRACE" : "START_REQUESTED");
  }
  return true;
}

int
payment_origin_handle_reply(origin_circuit_t *circ, crypt_path_t *layer,
                             const relay_msg_t *msg, uint64_t now_ms)
{
  payment_origin_hop_t *h = layer ? layer->payment_profile : NULL;
  if (!h || h->circ != circ || h->closed || h->failed || !h->ready ||
      !layer->payment_keys || !msg || msg->stream_id || msg->is_relay_early)
    return 0;
  payment_profile_command_t command = (payment_profile_command_t)msg->command;
  if (command != PAYMENT_PROFILE_COMMITTED && command != PAYMENT_PROFILE_RENEWED &&
      command != PAYMENT_PROFILE_STARTED_STATUS) return 0;
  const uint8_t *key = command == PAYMENT_PROFILE_RENEWED ?
    layer->payment_keys->renew_reply : layer->payment_keys->start_reply;
  payment_profile_message_t m;
  if (payment_profile_decode(&m, command, msg->body, msg->length, key,
                              layer->payment_keys->binding)) return 0;
  const uint8_t *nonce = command == PAYMENT_PROFILE_COMMITTED ? m.u.committed.nonce :
    command == PAYMENT_PROFILE_RENEWED ? m.u.renewed.nonce : m.u.started.nonce;
  const uint8_t *digest = command == PAYMENT_PROFILE_COMMITTED ?
    m.u.committed.request_digest : command == PAYMENT_PROFILE_RENEWED ?
    m.u.renewed.request_digest : m.u.started.request_digest;
  payment_origin_operation_t *op;
  for (op = h->operations; op; op = op->hop_next) {
    if (tor_memeq(op->nonce, nonce, 16) && tor_memeq(op->digest, digest, 32)) break;
  }
  if (!op || !op->transmissions || now_ms < op->first_send_ms ||
      (h->status_seen && now_ms < h->observed_ms)) return 0;
  if (command == PAYMENT_PROFILE_COMMITTED && op->kind == PAYMENT_ORIGIN_COMMIT) {
    payment_profile_committed_t *r = &m.u.committed;
    if (!r->status && (tor_memneq(r->terms,h->terms,32) ||
                       tor_memneq(r->allocation,h->initial,32))) {
      fail_profile(h); return 0;
    }
    if (r->setup_remaining_ms > h->policy.setup_timeout_ms) {
      fail_profile(h); return 0;
    }
    if (op->result_seen) {
      if (op->relay_status != r->status) fail_profile(h);
      return 0;
    }
    op->result_seen = true; op->relay_status = r->status;
    op->phase = r->status ? PAYMENT_ORIGIN_REFUSED : PAYMENT_ORIGIN_VERIFIED;
    if (!r->status) {
      h->confirmed = true; h->state = 1;
      learn_deadline(&h->setup_deadline_ms,reply_deadline(op,r->setup_remaining_ms));
      changed(h,"COMMITTED");
    } else changed(h,"RENEW_REFUSED");
  } else if (command == PAYMENT_PROFILE_STARTED_STATUS &&
             (op->kind == PAYMENT_ORIGIN_START || op->kind == PAYMENT_ORIGIN_QUERY)) {
    if (!apply_status(h,op,&m.u.started,now_ms)) fail_profile(h);
  } else if (command == PAYMENT_PROFILE_RENEWED && op->kind == PAYMENT_ORIGIN_RENEW) {
    payment_profile_renewed_t *r = &m.u.renewed;
    if (r->period != op->period || tor_memneq(r->terms,h->terms,32) ||
        (!r->status && tor_memneq(r->allocation,op->allocation,32)) ||
        (r->status == 1 && tor_memneq(r->allocation,op->allocation,32)) ||
        (op->result_seen && r->status != op->relay_status &&
          !(op->relay_status == 0 && r->status == 1))) {
      fail_profile(h); return 0;
    }
    op->relay_status = r->status; op->result_seen = true;
    op->phase = r->status == 0 ? PAYMENT_ORIGIN_ADMITTED :
                r->status == 1 ? PAYMENT_ORIGIN_ACTIVE : PAYMENT_ORIGIN_REFUSED;
    if (r->status < 2) {
      op->allocation_available = true;
      uint64_t safe = reply_deadline(op,remaining_ms(r->admit_before_ms,r->elapsed_ms));
      if (safe < op->deadline_ms) op->deadline_ms = safe;
      if (r->status == 1) {
        if (r->elapsed_ms < r->activation_ms ||
            r->elapsed_ms >= h->policy.max_age_ms) {
          fail_profile(h); return 0;
        }
        /* Never pair this new allocation with the old status round/timers.
         * Exact historical ACTIVE replays only refine the retained operation;
         * they cannot move the live profile backward or reset any deadline. */
        if (r->period>h->active_period && r->period>h->pending_active_period)
          h->pending_active_period=r->period;
      }
      changed(h,"RENEW_ADMITTED");
    } else changed(h,"RENEW_REFUSED");
  }
  schedule_origin_timer(now_ms);
  return 0;
}

payment_origin_result_t
payment_origin_get_registration(const origin_circuit_t *circ,uint16_t index,
                                 uint64_t now_ms,
                                 payment_origin_registration_t *out)
{
  if (!out) return PAYMENT_ORIGIN_INVALID;
  memset(out,0,sizeof(*out));
  if (!circ || circ->base_.marked_for_close || !index || index>16)
    return PAYMENT_ORIGIN_CLOSED;
  payment_origin_hop_t *h=get_hop(circ,index);
  if (!h) return PAYMENT_ORIGIN_UNSUPPORTED;
  if (h->closed) return PAYMENT_ORIGIN_CLOSED;
  if (!h->ready || !h->hop->payment_export_requested || !h->hop->payment_keys)
    return PAYMENT_ORIGIN_UNCONFIRMED;
  if (now_ms<h->constructed_ms) return PAYMENT_ORIGIN_INVALID;
  if (payment_profile_policy_encode(out->policy,sizeof(out->policy),&h->policy))
    return PAYMENT_ORIGIN_INVALID;
  memcpy(out->terms,h->terms,32); memcpy(out->initial,h->initial,32);
  memcpy(out->binding,h->hop->payment_keys->binding,32);
  memcpy(out->ids,h->ids,sizeof(out->ids));
  out->revision=control_payment_revision(TO_CIRCUIT(circ));
  return PAYMENT_ORIGIN_OK;
}

payment_origin_result_t
payment_origin_get(const origin_circuit_t *circ, uint16_t index,
    const uint8_t operation[16], bool initial, uint64_t now_ms,
    payment_origin_snapshot_t *out)
{
  if (!out) return PAYMENT_ORIGIN_INVALID;
  memset(out,0,sizeof(*out));
  payment_origin_hop_t *h = get_hop(circ,index);
  if (!h || h->closed) return PAYMENT_ORIGIN_CLOSED;
  if (now_ms < h->constructed_ms || (h->status_seen && now_ms < h->observed_ms))
    return PAYMENT_ORIGIN_INVALID;
  payment_origin_operation_t *op = operation ? find_operation(h,operation) : NULL;
  if (operation && (!op || ((op->kind == PAYMENT_ORIGIN_RENEW) == initial)))
    return PAYMENT_ORIGIN_UNKNOWN_OPERATION;
  if (h->pending_active_period ||
      (!h->failed && h->status_seen && h->state == 3 &&
       now_ms >= h->round_deadline_ms && now_ms < h->hard_deadline_ms))
    return PAYMENT_ORIGIN_OBSERVATION_PENDING;
  if (!initial && (!h->confirmed || !h->status_seen || !h->current_round))
    return PAYMENT_ORIGIN_UNCONFIRMED;
  out->revision = control_payment_revision(TO_CIRCUIT(circ));
  out->confirmed = h->confirmed;
  if (h->confirmed) {
    memcpy(out->terms,h->terms,32); memcpy(out->initial_allocation,h->initial,32);
    memcpy(out->active_allocation,h->active_allocation,32);
    out->state = h->state;
    out->setup_available = !h->current_round;
    out->setup_remaining_ms = h->failed ? 0 :remaining_ms(h->setup_deadline_ms,now_ms);
  }
  out->status_available = h->status_seen;
  out->relay_revision_available = h->status_seen;
  out->relay_revision = h->relay_revision;
  out->current_round = h->current_round; out->active_period = h->active_period;
  out->schedule_available = h->status_seen && h->current_round && !h->failed;
  if (h->status_seen && h->current_round) {
    out->elapsed_upper_ms = saturating_add(h->elapsed_upper_ms,now_ms-h->observed_ms);
    if (!h->failed) {
      out->round_remaining_ms = remaining_ms(h->round_deadline_ms,now_ms);
      out->enforcement_remaining_ms = remaining_ms(h->enforcement_deadline_ms,now_ms);
      out->hard_age_remaining_ms = remaining_ms(h->hard_deadline_ms,now_ms);
      uint64_t next=h->active_period+1;
      if (next < h->policy.max_periods &&
          next < UINT64_MAX/(10*PAYMENT_PROFILE_ROUND_MS) &&
          (next+1)*10*PAYMENT_PROFILE_ROUND_MS <= h->policy.max_age_ms) {
        out->admission_available=true;
        out->admission_remaining_ms=remaining_ms(
            next*10*PAYMENT_PROFILE_ROUND_MS-PAYMENT_PROFILE_ROUND_MS,
            out->elapsed_upper_ms);
        if (out->hard_age_remaining_ms < out->admission_remaining_ms)
          out->admission_remaining_ms=out->hard_age_remaining_ms;
      }
    }
  }
  if (op) {
    out->operation_available = true;
    memcpy(out->operation,op->id,16); memcpy(out->request_digest,op->digest,32);
    out->kind = op->kind; out->phase = op->phase; out->period = op->period;
    out->transmissions = op->transmissions;
    out->relay_status_available = op->result_seen;
    out->relay_status = op->relay_status;
    out->allocation_available = op->allocation_available;
    if (op->allocation_available) memcpy(out->allocation_digest,op->allocation,32);
    if (op->kind == PAYMENT_ORIGIN_RENEW && op->period>h->active_period &&
        op->phase != PAYMENT_ORIGIN_REFUSED) {
      out->admission_available=true;
      out->admission_remaining_ms = remaining_ms(op->deadline_ms,now_ms);
    }
  }
  return PAYMENT_ORIGIN_OK;
}

static uint64_t
next_operation_deadline(const payment_origin_operation_t *op)
{
  static const uint64_t initial_delays[] = {0,1000,3000,7000};
  static const uint64_t renewal_delays[] = {0,10000,30000,60000};
  if (!op->owner) return op->retire_ms;
  if (!pending(op)) return UINT64_MAX;
  uint64_t due = op->deadline_ms;
  if (op->kind != PAYMENT_ORIGIN_QUERY && op->transmissions < 4) {
    const uint64_t *delays = op->kind == PAYMENT_ORIGIN_RENEW ?
                              renewal_delays : initial_delays;
    uint64_t retry = saturating_add(op->first_send_ms,delays[op->transmissions]);
    if (retry < due) due = retry;
  }
  return due;
}

static void
origin_timer_callback(tor_timer_t *timer, void *arg, const monotime_t *now)
{
  (void)timer; (void)arg; (void)now;
  payment_origin_tick(monotime_absolute_msec());
}

static void
schedule_origin_timer(uint64_t now_ms)
{
  if (origin_timer_dispatching) return;
  uint64_t due = UINT64_MAX;
  for (payment_origin_operation_t *op=origin_operations;op;op=op->global_next) {
    uint64_t candidate=next_operation_deadline(op);
    if (candidate<due) due=candidate;
  }
  for (payment_origin_hop_t *h=origin_hops;h;h=h->next) {
    uint64_t candidate=h->current_round ? h->hard_deadline_ms : h->setup_deadline_ms;
    if (!h->failed && !h->closed && candidate<due) due=candidate;
  }
  if (due==UINT64_MAX) { if (origin_timer) timer_disable(origin_timer); return; }
  if (!origin_timer) origin_timer=timer_new(origin_timer_callback,NULL);
  uint64_t delay=remaining_ms(due,now_ms);
  if (!delay) delay=1;
  if (delay>60000) delay=60000;
  struct timeval tv={(time_t)(delay/1000),(suseconds_t)(delay%1000)*1000};
  timer_schedule(origin_timer,&tv);
}

void
payment_origin_tick(uint64_t now_ms)
{
  origin_timer_dispatching=true;
  for (payment_origin_hop_t *h=origin_hops;h;h=h->next) {
    uint64_t deadline=h->current_round?h->hard_deadline_ms:h->setup_deadline_ms;
    if (!h->closed && now_ms>=deadline) {
      fail_profile(h);
      if (h->circ && (h->confirmed || !h->circ->base_.free_capacity) &&
          !h->circ->base_.marked_for_close)
        circuit_mark_for_close(TO_CIRCUIT(h->circ),END_CIRC_REASON_TIMEOUT);
    }
  }
  payment_origin_operation_t **link=&origin_operations;
  while (*link) {
    payment_origin_operation_t *op=*link;
    if (!op->owner && now_ms>=op->retire_ms) {
      *link=op->global_next;
      protocol_budget_memory_t memory=op->memory;
      bool operation_held=op->operation_held;
      --origin_operation_count;
      memwipe(op,0,sizeof(*op)); tor_free(op);
      payment_resources_release(&memory);
      payment_resources_operation_release(&operation_held);
      continue;
    }
    if (op->owner && pending(op) && now_ms>=next_operation_deadline(op)) {
      if (now_ms>=op->deadline_ms || op->owner->failed) {
        op->phase=PAYMENT_ORIGIN_UNCERTAIN;
        changed(op->owner,"EXPIRED");
      } else send_operation(op,now_ms);
    }
    link=&op->global_next;
  }
  origin_timer_dispatching=false;
  schedule_origin_timer(now_ms);
}

void
payment_origin_close(origin_circuit_t *circ)
{
  if (!circ) return;
  uint64_t now_ms=monotime_absolute_msec();
  for (payment_origin_hop_t *h=origin_hops;h;h=h->next) {
    if (h->circ!=circ || h->closed) continue;
    h->closed=true;
    payment_origin_operation_t *op=h->operations;
    while (op) {
      payment_origin_operation_t *next=op->hop_next;
      op->phase=PAYMENT_ORIGIN_OPERATION_CLOSED; op->owner=NULL;
      op->retire_ms=saturating_add(now_ms,ORIGIN_TOMBSTONE_MS);
      if (op->wire) { memwipe(op->wire,0,PAYMENT_PROFILE_WIRE_LEN); tor_free(op->wire); }
      op->hop_next=NULL;
      op=next;
    }
    h->operations=NULL;
  }
  control_payment_circuit_closed(TO_CIRCUIT(circ));
  schedule_origin_timer(now_ms);
}

void
payment_origin_hop_free(crypt_path_t *hop)
{
  payment_origin_hop_t *h=hop?hop->payment_profile:NULL;
  if (!h) return;
  payment_origin_close(h->circ);
  payment_origin_hop_t **link=&origin_hops;
  while (*link && *link!=h) link=&(*link)->next;
  if (*link) *link=h->next;
  protocol_budget_memory_t memory=h->memory;
  memwipe(h,0,sizeof(*h)); tor_free(h);
  payment_resources_release(&memory);
  hop->payment_profile=NULL;
  if (!origin_hops && !origin_operations) {
    timer_free(origin_timer);
    payment_resources_release(&origin_timer_memory);
  }
}


int
payment_origin_configure_query_timeout(uint32_t timeout_ms)
{
  if (origin_hops || origin_operations || !timeout_ms || timeout_ms > 60000)
    return -1;
  query_timeout_ms = timeout_ms;
  return 0;
}

int
payment_origin_free_all(void)
{
  if (origin_hops) return -1;
  while (origin_operations) {
    payment_origin_operation_t *op = origin_operations;
    origin_operations = op->global_next;
    protocol_budget_memory_t memory=op->memory;
    bool operation_held=op->operation_held;
    if (op->wire) { memwipe(op->wire,0,PAYMENT_PROFILE_WIRE_LEN); tor_free(op->wire); }
    memwipe(op,0,sizeof(*op)); tor_free(op);
    payment_resources_release(&memory);
    payment_resources_operation_release(&operation_held);
  }
  origin_operation_count = 0;
  timer_free(origin_timer);
  payment_resources_release(&origin_timer_memory);
  return 0;
}
