/* Copyright (c) 2026, The El Tor Project. */
/* See LICENSE for licensing information. */
#include "orconfig.h"
#include "core/or/or.h"
#include "core/or/origin_circuit_st.h"
#include "core/or/crypt_path_st.h"
#include "core/or/crypt_path.h"
#include "core/or/cpath_build_state_st.h"
#include "core/or/extend_info_st.h"
#include "core/or/circuitlist.h"
#include "feature/payment/payment_origin.h"
#include "feature/payment/relay_payments.h"
#include "feature/payment/payment_resources.h"
#include "lib/time/compat_time.h"
#include "lib/evloop/timers.h"
#include "test/test.h"

static void
test_payment_resources_shared_memory(void *arg)
{
  protocol_budget_limits_t limits;
  protocol_budget_memory_t a = {0}, b = {0}, c = {0};
  protocol_budget_t *owner;
  uint32_t baseline, available;
  (void)arg;
  monotime_enable_test_mocking();
  monotime_set_mock_time_nsec(INT64_C(1000000000));
  protocol_budget_default_limits(&limits);
  limits.arena_bytes = 1024;
  limits.max_slot_bytes = 512;
  limits.max_slots = 2;
  tt_int_op(payment_resources_configure(&limits), OP_EQ, 0);
  owner = payment_resources_protocol();
  baseline = owner->arena_used;
  available = limits.arena_bytes - baseline;
  tt_uint_op(baseline, OP_GT, 0);
  tt_ptr_op(payment_resources_protocol(), OP_EQ, owner);
  tt_int_op(payment_resources_configure(&limits), OP_EQ, -1);
  tt_int_op(payment_resources_reserve(&a, available / 2), OP_EQ, PROTOCOL_BUDGET_OK);
  tt_int_op(payment_resources_reserve(&b, available - available / 2), OP_EQ, PROTOCOL_BUDGET_OK);
  tt_int_op(payment_resources_reserve(&c, sizeof(c)), OP_EQ,
            PROTOCOL_BUDGET_REFUSE);
  tt_uint_op(owner->arena_used, OP_EQ, 1024);
  tt_int_op(payment_resources_free_all(), OP_EQ, -1);
  owner->crypto_credit_milli = 0;
  tt_int_op(payment_resources_release(&a), OP_EQ, PROTOCOL_BUDGET_OK);
  tt_int_op(payment_resources_release(&a), OP_EQ, PROTOCOL_BUDGET_OK);
  tt_uint_op(owner->arena_used, OP_EQ, baseline + available - available / 2);
  tt_u64_op(owner->crypto_credit_milli, OP_EQ, 0);
  /* Clock rollback stops admissions while still permitting real cleanup. */
  monotime_set_mock_time_nsec(INT64_C(900000000));
  tt_int_op(payment_resources_release(&b), OP_EQ, PROTOCOL_BUDGET_OK);
  tt_uint_op(owner->arena_used, OP_EQ, baseline);
  tt_u64_op(owner->crypto_credit_milli, OP_EQ, 0);
  tt_int_op(payment_resources_reserve(&c, sizeof(c)), OP_EQ,
            PROTOCOL_BUDGET_CLOCK_ERROR);
  monotime_set_mock_time_nsec(INT64_C(1000000000));
  tt_int_op(payment_resources_reserve(&c, SIZE_MAX), OP_EQ,
            PROTOCOL_BUDGET_REFUSE);
  tt_int_op(payment_resources_free_all(), OP_EQ, 0);
 done:
  (void)payment_resources_release(&a);
  (void)payment_resources_release(&b);
  (void)payment_resources_release(&c);
  (void)payment_resources_free_all();
  monotime_disable_test_mocking();
}

static void
test_payment_resources_operations(void *arg)
{
  bool held[PAYMENT_RESOURCES_OPERATIONS + 1] = {false};
  (void)arg;
  for (unsigned i = 0; i < PAYMENT_RESOURCES_OPERATIONS; ++i)
    tt_assert(payment_resources_operation_reserve(&held[i]));
  tt_uint_op(payment_resources_operations_used(), OP_EQ, 4096);
  tt_assert(payment_resources_operation_reserve(&held[0]));
  tt_assert(!payment_resources_operation_reserve(
              &held[PAYMENT_RESOURCES_OPERATIONS]));
  tt_uint_op(payment_resources_operations_used(), OP_EQ, 4096);
  tt_int_op(payment_resources_free_all(), OP_EQ, -1);
  payment_resources_operation_release(&held[0]);
  payment_resources_operation_release(&held[0]);
  tt_uint_op(payment_resources_operations_used(), OP_EQ, 4095);
  tt_assert(payment_resources_operation_reserve(
              &held[PAYMENT_RESOURCES_OPERATIONS]));
 done:
  for (unsigned i = 0; i <= PAYMENT_RESOURCES_OPERATIONS; ++i)
    payment_resources_operation_release(&held[i]);
  tt_uint_op(payment_resources_operations_used(), OP_EQ, 0);
  (void)payment_resources_free_all();
}

static void
test_payment_resources_accessors(void *arg)
{
  free_capacity_t *free;
  protocol_budget_t *protocol;
  protocol_budget_limits_t invalid;
  protocol_budget_memory_t memory = {0};
  size_t cost;
  uint32_t baseline;
  (void)arg;
  protocol_budget_default_limits(&invalid);
  ++invalid.crypto_rate;
  tt_int_op(payment_resources_configure(&invalid), OP_EQ, -1);
  free = payment_resources_free();
  protocol = payment_resources_protocol();
  baseline = protocol->arena_used;
  tt_uint_op(baseline, OP_GT, 0);
  tt_ptr_op(payment_resources_free(), OP_EQ, free);
  tt_ptr_op(payment_resources_protocol(), OP_EQ, protocol);
  free->bytes.credit_milli = 0;
  (void)payment_resources_free();
  (void)payment_resources_protocol();
  tt_u64_op(free->bytes.credit_milli, OP_EQ, 0);
  /* Timer reservation uses its real allocation size, not a guessed payload. */
  cost = timer_memory_cost() + sizeof(memory);
  tt_assert(cost >= sizeof(memory));
  tt_int_op(payment_resources_reserve(&memory, cost), OP_EQ, PROTOCOL_BUDGET_OK);
  tt_uint_op(protocol->arena_used, OP_EQ, baseline + cost);
  tt_int_op(payment_resources_release(&memory), OP_EQ, PROTOCOL_BUDGET_OK);
  tt_uint_op(protocol->arena_used, OP_EQ, baseline);
  tt_int_op(payment_resources_free_all(), OP_EQ, 0);
 done:
  (void)payment_resources_release(&memory);
  (void)payment_resources_free_all();
}

static void
test_payment_resources_shared_slots(void *arg)
{
  protocol_budget_limits_t limits;
  protocol_budget_slot_t slot = {0};
  bool a = false, b = false;
  uint64_t now_ms = monotime_absolute_msec();
  (void)arg;
  protocol_budget_default_limits(&limits);
  limits.max_slots = 2;
  tt_int_op(payment_resources_configure(&limits), OP_EQ, 0);
  protocol_budget_t *owner = payment_resources_protocol();
  now_ms = owner->last_ms;
  tt_int_op(protocol_budget_slot_reserve(owner, &slot, sizeof(slot),
      now_ms + 1000, now_ms), OP_EQ, PROTOCOL_BUDGET_OK);
  tt_assert(payment_resources_operation_reserve(&a));
  tt_assert(!payment_resources_operation_reserve(&b));
  tt_uint_op(owner->slots, OP_EQ, 2);
  payment_resources_operation_release(&a);
  tt_uint_op(owner->slots, OP_EQ, 1);
  tt_assert(payment_resources_operation_reserve(&b));
 done:
  payment_resources_operation_release(&a);
  payment_resources_operation_release(&b);
  if (slot.state != PROTOCOL_BUDGET_SLOT_UNUSED)
    (void)protocol_budget_slot_expire(&slot, slot.generation, now_ms + 1000);
  (void)payment_resources_free_all();
}

static origin_circuit_t *
constructor_fixture(void)
{
  origin_circuit_t *circ = origin_circuit_new();
  extend_info_t info = {0};
  info.supports_ntor_v3 = info.payment_free_v1 = true;
  circ->base_.purpose = CIRCUIT_PURPOSE_CONTROLLER;
  circ->build_state = tor_malloc_zero(sizeof(*circ->build_state));
  circ->build_state->desired_path_len = 16;
  circ->payment_payhash_capacity = 16 * (40 + 1 + 768 + 1) + 1;
  circ->payhashes = tor_malloc_zero(circ->payment_payhash_capacity);
  memset(circ->payhashes, 'a', PAYMENT_ORIGIN_CONSTRUCTION_PAYHASH_BYTES);
  circ->relay_payments = relay_payments_new();
  for (unsigned i = 0; i < 16; ++i) {
    relay_payment_item_t *item = relay_payment_item_new();
    item->fingerprint = tor_malloc_zero(41);
    memset(item->fingerprint, 'a', 40);
    item->handshake_payment_hash = tor_malloc_zero(65);
    memset(item->handshake_payment_hash, '1', 64);
    item->handshake_preimage = tor_strdup(item->handshake_payment_hash);
    item->payhashes = tor_malloc_zero(641);
    memset(item->payhashes, '2', 640);
    item->wire_format = tor_malloc_zero(782);
    memset(item->wire_format, '3', 781);
    relay_payments_add_item(circ->relay_payments, item);
    if (cpath_append_hop(&circ->cpath, &info) < 0) return circ;
  }
  return circ;
}

static void
test_payment_resources_constructor_graph(void *arg)
{
  origin_circuit_t *a = NULL, *b = NULL;
  protocol_budget_memory_t fill = {0};
  protocol_budget_limits_t limits;
  size_t cost = 0, other_cost = 0;
  uint32_t baseline, with_graph;
  (void)arg;
  monotime_enable_test_mocking();
  monotime_set_mock_time_nsec(INT64_C(1000000000));
  monotime_coarse_set_mock_time_nsec(INT64_C(1000000000));
  timers_initialize();
  protocol_budget_default_limits(&limits);
  limits.arena_bytes = 512 * 1024;
  tt_int_op(payment_resources_configure(&limits), OP_EQ, 0);
  protocol_budget_t *owner = payment_resources_protocol();
  baseline = owner->arena_used;
  a = constructor_fixture(); b = constructor_fixture();
  tt_int_op(payment_origin_construction_cost(a, &cost), OP_EQ, 0);
  tt_uint_op(cost, OP_GT, 16 * PAYMENT_ORIGIN_NATIVE_CRYPTO_RESERVE);
  tt_int_op(payment_origin_reserve_construction(a), OP_EQ, 0);
  tt_uint_op(a->payment_construction_hops, OP_EQ, 16);
  tt_uint_op(a->payment_construction_memory.allocation_bytes, OP_EQ, cost);
  tt_uint_op(owner->arena_used, OP_EQ, baseline + cost);
  with_graph = owner->arena_used;
  tt_int_op(payment_origin_reserve_construction(a), OP_EQ, 0);
  tt_uint_op(owner->arena_used, OP_EQ, with_graph); /* no duplicate charge */
  /* These reservations precede all exporter, ntor and relay crypto work. */
  crypt_path_t *hop = a->cpath;
  do {
    tt_assert(!hop->payment_export_requested);
    tt_ptr_op(hop->payment_keys, OP_EQ, NULL);
    tt_ptr_op(hop->payment_profile, OP_EQ, NULL);
    tt_uint_op(hop->handshake_state.tag, OP_EQ, 0);
    hop = hop->next;
  } while (hop != a->cpath);
  tt_int_op(payment_origin_construction_cost(b, &other_cost), OP_EQ, 0);
  tt_int_op(payment_resources_reserve(&fill,
      limits.arena_bytes - owner->arena_used - other_cost + 1), OP_EQ,
      PROTOCOL_BUDGET_OK);
  uint32_t before = owner->arena_used;
  uint64_t credit = owner->crypto_credit_milli;
  tt_int_op(payment_origin_reserve_construction(b), OP_EQ, -1);
  tt_assert(!b->payment_construction_memory.active);
  tt_uint_op(owner->arena_used, OP_EQ, before);
  tt_u64_op(owner->crypto_credit_milli, OP_EQ, credit);
  tt_ptr_op(b->base_.free_capacity, OP_EQ, NULL);
  /* A seventeenth native path entry is refused without a shared reservation,
   * exporter flag, free admission or attempted crypto credit debit. */
  extend_info_t extra = {0};
  tt_int_op(cpath_append_hop(&b->cpath, &extra), OP_EQ, 0);
  tt_int_op(payment_origin_construction_cost(b, &other_cost), OP_EQ, -1);
  tt_int_op(payment_origin_reserve_construction(b), OP_EQ, -1);
  tt_assert(!b->payment_construction_memory.active);
  tt_uint_op(owner->arena_used, OP_EQ, before);
  tt_u64_op(owner->crypto_credit_milli, OP_EQ, credit);
  /* Close/partial native cpath destruction does not release retained circuit,
   * proof strings and constructor backing. Only full native destruction does. */
  payment_origin_close(a);
  tt_uint_op(owner->arena_used, OP_EQ, before);
  circuit_clear_cpath(a);
  tt_uint_op(owner->arena_used, OP_EQ, before);
  circuit_free_all(); a = b = NULL;
  tt_uint_op(owner->arena_used, OP_EQ, baseline + fill.allocation_bytes);
  tt_int_op(payment_resources_release(&fill), OP_EQ, PROTOCOL_BUDGET_OK);
  tt_uint_op(owner->arena_used, OP_EQ, baseline);
  tt_int_op(payment_resources_free_all(), OP_EQ, 0);
 done:
  circuit_free_all();
  (void)payment_resources_release(&fill);
  (void)payment_origin_free_all();
  (void)payment_resources_free_all();
  timers_shutdown(); monotime_disable_test_mocking();
}

#define RESOURCE_TEST(name) \
  { #name, test_payment_resources_##name, TT_FORK, NULL, NULL }
struct testcase_t payment_resources_tests[] = {
  RESOURCE_TEST(shared_memory),
  RESOURCE_TEST(operations),
  RESOURCE_TEST(accessors),
  RESOURCE_TEST(shared_slots),
  RESOURCE_TEST(constructor_graph),
  END_OF_TESTCASES
};
