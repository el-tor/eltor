#include "orconfig.h"
#include "core/or/or.h"
#include "feature/payment/payment_util.h"
#include "test/test.h"
#include "lib/log/log.h"
#include <stddef.h>
#include "core/or/origin_circuit_st.h"
#include "core/or/crypt_path_st.h"
#include "feature/payment/relay_payments.h"

// To test run:
// ./src/test/test payment/relay_payments_basic --verbose

// Add this test function before the PAYMENT_TESTS definition
static void
test_payment_util_relay_payments_basic(void *arg)
{
  (void)arg;

  // Create a relay_payments collection
  relay_payments_t *payments = relay_payments_new();
  tt_assert(payments);
  tt_int_op(smartlist_len(payments), OP_EQ, 0);

  // Create and add first item
  relay_payment_item_t *item1 = relay_payment_item_new();
  tt_assert(item1);
  item1->fingerprint = tor_strdup("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
  item1->handshake_payment_hash = tor_strdup("eltor_payhash_handshake1");
  item1->handshake_preimage = tor_strdup("preimage_for_handshake1");
  item1->payhashes = tor_strdup("payment_id_hash_r1+payment_id_hash_r2");
  item1->wire_format =
      tor_strdup("eltor_payhash_handshake1preimage_for_handshake1payment_id_"
                 "hash_r1+payment_id_hash_r2");

  relay_payments_add_item(payments, item1);
  tt_int_op(smartlist_len(payments), OP_EQ, 1);

  // Create and add second item
  relay_payment_item_t *item2 = relay_payment_item_new();
  tt_assert(item2);
  item2->fingerprint = tor_strdup("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB");
  item2->handshake_payment_hash = tor_strdup("eltor_payhash_handshake2");
  item2->handshake_preimage = tor_strdup("preimage_for_handshake2");
  item2->payhashes = tor_strdup("payment_id_hash_r3+payment_id_hash_r4");
  item2->wire_format =
      tor_strdup("eltor_payhash_handshake2preimage_for_handshake2payment_id_"
                 "hash_r3+payment_id_hash_r4");

  relay_payments_add_item(payments, item2);
  tt_int_op(smartlist_len(payments), OP_EQ, 2);

  // Test finding by fingerprint
  relay_payment_item_t *found = relay_payments_find_by_fingerprint(
      payments, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
  tt_assert(found);
  tt_str_op(found->handshake_payment_hash, OP_EQ, "eltor_payhash_handshake1");

  found = relay_payments_find_by_fingerprint(
      payments, "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB");
  tt_assert(found);
  tt_str_op(found->handshake_payment_hash, OP_EQ, "eltor_payhash_handshake2");

  // Test finding non-existent fingerprint
  found = relay_payments_find_by_fingerprint(
      payments, "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC");
  tt_assert(!found);

  // Test cloning an item
  relay_payment_item_t *cloned_item = relay_payment_item_clone(item1);
  tt_assert(cloned_item);
  tt_str_op(cloned_item->fingerprint, OP_EQ, item1->fingerprint);
  tt_ptr_op(cloned_item->fingerprint, OP_NE,
            item1->fingerprint); // Different pointers
  tt_str_op(cloned_item->handshake_payment_hash, OP_EQ,
            item1->handshake_payment_hash);
  tt_str_op(cloned_item->wire_format, OP_EQ, item1->wire_format);

  // Test cloning the whole collection
  relay_payments_t *cloned_payments = relay_payments_clone(payments);
  tt_assert(cloned_payments);
  tt_int_op(smartlist_len(cloned_payments), OP_EQ, smartlist_len(payments));

  // Verify cloned items have correct data
  relay_payment_item_t *cloned_first = smartlist_get(cloned_payments, 0);
  tt_assert(cloned_first);
  tt_str_op(cloned_first->fingerprint, OP_EQ, item1->fingerprint);

  // Test validation
  tt_int_op(relay_payment_item_is_valid(item1), OP_EQ, 1);

  // Test invalid item
  relay_payment_item_t *invalid_item = relay_payment_item_new();
  tt_int_op(relay_payment_item_is_valid(invalid_item), OP_EQ, 0);

  // Test with just fingerprint
  invalid_item->fingerprint = tor_strdup("FINGERPRINT");
  tt_int_op(relay_payment_item_is_valid(invalid_item), OP_EQ, 0);

  // Add required handshake_payment_hash to make valid
  invalid_item->handshake_payment_hash = tor_strdup("HASH");
  tt_int_op(relay_payment_item_is_valid(invalid_item), OP_EQ, 1);

done:
  relay_payment_item_free(invalid_item);
  relay_payment_item_free(cloned_item);
  relay_payments_free(payments);
  relay_payments_free(cloned_payments);
}

// TODO El Tor client and relay flows with new relay payments struct
// 1. client_get_circ_payhashes_from_rpc(rpc)
// 2. client_get_hop_payhashes_from_circ_payhashes(circ->payhash)
// 3. relay_get_payhashes_from_encrypted_cell(string enc_payload)

#define PAYMENT_TESTS(name) \
  {#name, test_payment_util_##name, TT_FORK, NULL, NULL}

struct testcase_t payment_tests[] = {PAYMENT_TESTS(relay_payments_basic),
                                     END_OF_TESTCASES};
