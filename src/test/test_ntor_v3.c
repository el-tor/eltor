/* Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2021, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include "orconfig.h"
#define ONION_NTOR_V3_PRIVATE
#define CONTROL_EVENTS_PRIVATE
#include "core/or/or.h"
#include "core/or/or_connection_st.h"
#include "feature/payment/free_capacity_hooks.h"
#include "feature/payment/payment_resources.h"
#include "feature/payment/payment_initial.h"
#include "feature/control/control_events.h"
#include "lib/evloop/timers.h"
#include "test/test.h"
#include "test/test_helpers.h"
#include "lib/crypt_ops/crypto_curve25519.h"
#include "lib/crypt_ops/crypto_util.h"
#include "lib/crypt_ops/crypto_ed25519.h"
#include "core/crypto/onion_ntor_v3.h"
#include "core/crypto/onion_crypto.h"
#include "core/or/extend_info_st.h"
#include "core/or/crypt_path_st.h"
#include "core/or/crypt_path.h"
#include "core/or/circuitbuild.h"
#include "core/or/circuitlist.h"
#include "core/or/origin_circuit_st.h"
#include "core/or/cell_st.h"
#include "core/or/onion.h"
#include "core/or/cpath_build_state_st.h"
#define TOR_CONGESTION_CONTROL_PRIVATE
#define TOR_CONGESTION_CONTROL_COMMON_PRIVATE
#include "core/or/congestion_control_st.h"
#include "core/or/congestion_control_common.h"
#include "app/config/config.h"

#define unhex(arry, s)                                                  \
  { tt_int_op(sizeof(arry), OP_EQ,                                      \
              base16_decode((char*)arry, sizeof(arry), s, strlen(s)));  \
  }

static void
test_ntor3_testvecs(void *arg)
{
  bool payment_requested = arg != NULL;
  payment_profile_export_t client_export = {0}, server_export = {0};
  char *mem_op_hex_tmp = NULL; // temp val to make test_memeq_hex work.

  ntor3_server_handshake_state_t *relay_state = NULL;
  uint8_t *onion_skin = NULL;
  size_t onion_skin_len;
  ntor3_handshake_state_t *client_state = NULL;
  uint8_t *cm = NULL, *sm = NULL;
  size_t cm_len, sm_len;
  di_digest256_map_t *private_keys = NULL;
  uint8_t *server_handshake = NULL;
  size_t server_handshake_len;

  // Test vectors from python implementation, confirmed with rust
  // implementation.
  curve25519_keypair_t relay_keypair_b;
  curve25519_keypair_t client_keypair_x;
  curve25519_keypair_t relay_keypair_y;
  ed25519_public_key_t relay_id;

  unhex(relay_keypair_b.seckey.secret_key,
        "4051daa5921cfa2a1c27b08451324919538e79e788a81b38cbed097a5dff454a");
  unhex(relay_keypair_b.pubkey.public_key,
        "f8307a2bc1870b00b828bb74dbb8fd88e632a6375ab3bcd1ae706aaa8b6cdd1d");
  unhex(relay_id.pubkey,
        "9fad2af287ef942632833d21f946c6260c33fae6172b60006e86e4a6911753a2");
  unhex(client_keypair_x.seckey.secret_key,
        "b825a3719147bcbe5fb1d0b0fcb9c09e51948048e2e3283d2ab7b45b5ef38b49");
  unhex(client_keypair_x.pubkey.public_key,
        "252fe9ae91264c91d4ecb8501f79d0387e34ad8ca0f7c995184f7d11d5da4f46");
  unhex(relay_keypair_y.seckey.secret_key,
        "4865a5b7689dafd978f529291c7171bc159be076b92186405d13220b80e2a053");
  unhex(relay_keypair_y.pubkey.public_key,
        "4bf4814326fdab45ad5184f5518bd7fae25dc59374062698201a50a22954246d");

  uint8_t client_message[11];
  uint8_t verification[5];
  unhex(client_message, "68656c6c6f20776f726c64");
  unhex(verification, "78797a7a79");

  // ========= Client handshake 1.

  onion_skin_ntor3_create_nokeygen(
                    &client_keypair_x,
                    &relay_id,
                    &relay_keypair_b.pubkey,
                    verification,
                    sizeof(verification),
                    client_message,
                    sizeof(client_message),
                    &client_state,
                    &onion_skin,
                    &onion_skin_len, payment_requested);

  const char expect_client_handshake[] = "9fad2af287ef942632833d21f946c6260c"
    "33fae6172b60006e86e4a6911753a2f8307a2bc1870b00b828bb74dbb8fd88e632a6375"
    "ab3bcd1ae706aaa8b6cdd1d252fe9ae91264c91d4ecb8501f79d0387e34ad8ca0f7c995"
    "184f7d11d5da4f463bebd9151fd3b47c180abc9e044d53565f04d82bbb3bebed3d06cea"
    "65db8be9c72b68cd461942088502f67";

  tt_int_op(onion_skin_len, OP_EQ, strlen(expect_client_handshake)/2);
  test_memeq_hex(onion_skin, expect_client_handshake);

  // ========= Relay handshake.

  dimap_add_entry(&private_keys,
                  relay_keypair_b.pubkey.public_key,
                  &relay_keypair_b);

  uint64_t p_circ_id = 12345;
  uint64_t n_circ_id = 67890;
  int r = onion_skin_ntor3_server_handshake_part1(
                    private_keys,
                    &client_keypair_x,
                    &relay_id,
                    onion_skin,
                    onion_skin_len,
                    verification,
                    sizeof(verification),
                    &cm,
                    &cm_len,
                    &relay_state,
                    &p_circ_id,
                    &n_circ_id, payment_requested);
  tt_int_op(r, OP_EQ, 0);
  tt_int_op(cm_len, OP_EQ, sizeof(client_message));
  tt_mem_op(cm, OP_EQ, client_message, cm_len);

  uint8_t server_message[10];
  unhex(server_message, "486f6c61204d756e646f");

  uint8_t server_keys[256];
  onion_skin_ntor3_server_handshake_part2_nokeygen(
                    &relay_keypair_y,
                    relay_state,
                    verification,
                    sizeof(verification),
                    server_message,
                    sizeof(server_message),
                    &server_handshake,
                    &server_handshake_len,
                    server_keys,
                    sizeof(server_keys), &server_export);

  const char expect_server_handshake[] = "4bf4814326fdab45ad5184f5518bd7fae25"
    "dc59374062698201a50a22954246d2fc5f8773ca824542bc6cf6f57c7c29bbf4e5476461"
    "ab130c5b18ab0a91276651202c3e1e87c0d32054c";
  tt_int_op(server_handshake_len, OP_EQ, strlen(expect_server_handshake)/2);
  test_memeq_hex(server_handshake, expect_server_handshake);

  uint8_t expect_keys[256];
  unhex(expect_keys, "9c19b631fd94ed86a817e01f6c80b0743a43f5faebd39cfaa8b00f"
        "a8bcc65c3bfeaa403d91acbd68a821bf6ee8504602b094a254392a07737d5662768"
        "c7a9fb1b2814bb34780eaee6e867c773e28c212ead563e98a1cd5d5b4576f5ee61c"
        "59bde025ff2851bb19b721421694f263818e3531e43a9e4e3e2c661e2ad547d8984"
        "caa28ebecd3e4525452299be26b9185a20a90ce1eac20a91f2832d731b54502b097"
        "49b5a2a2949292f8cfcbeffb790c7790ed935a9d251e7e336148ea83b063a5618fc"
        "ff674a44581585fd22077ca0e52c59a24347a38d1a1ceebddbf238541f226b8f88d"
        "0fb9c07a1bcd2ea764bbbb5dacdaf5312a14c0b9e4f06309b0333b4a");
  tt_mem_op(server_keys, OP_EQ, expect_keys, 256);

  // ===== Client handshake 2

  uint8_t client_keys[256];
  r = onion_ntor3_client_handshake(
                  client_state,
                  server_handshake,
                  server_handshake_len,
                  verification,
                  sizeof(verification),
                  client_keys,
                  sizeof(client_keys),
                  &sm,
                  &sm_len, &client_export);

  tt_int_op(r, OP_EQ, 0);
  tt_int_op(sm_len, OP_EQ, sizeof(server_message));
  tt_mem_op(sm, OP_EQ, server_message, sizeof(server_message));
  tt_mem_op(client_keys, OP_EQ, server_keys, 256);
  tt_int_op(client_export.valid, OP_EQ, payment_requested);
  tt_int_op(server_export.valid, OP_EQ, payment_requested);
  tt_mem_op(&client_export.keys, OP_EQ, &server_export.keys,
            sizeof(client_export.keys));
  tt_int_op(client_state->payment_client_hdata != NULL,
            OP_EQ, payment_requested);
  tt_int_op(relay_state->payment_client_hdata != NULL,
            OP_EQ, payment_requested);
  if (payment_requested) {
    tt_size_op(client_state->payment_client_hdata_len, OP_EQ, onion_skin_len);
    tt_mem_op(client_state->payment_client_hdata, OP_EQ,
              onion_skin, onion_skin_len);
    tt_mem_op(relay_state->payment_client_hdata, OP_EQ,
              onion_skin, onion_skin_len);
    /* Corrupt server authentication: no partial payment key survives. */
    tor_free(sm);
    server_handshake[32] ^= 1;
    memset(&client_export, 0xff, sizeof(client_export));
    tt_int_op(onion_ntor3_client_handshake(client_state, server_handshake,
                  server_handshake_len, verification, sizeof(verification),
                  client_keys, sizeof(client_keys), &sm, &sm_len,
                  &client_export), OP_EQ, -1);
    tt_ptr_op(sm, OP_EQ, NULL);
    payment_profile_export_t zero = {0};
    tt_mem_op(&client_export, OP_EQ, &zero, sizeof(zero));
    /* Server-side all-zero DH failure also clears its dedicated result. */
    tor_free(server_handshake);
    memset(relay_state->client_key.public_key, 0, 32);
    memset(&server_export, 0xff, sizeof(server_export));
    tt_int_op(onion_skin_ntor3_server_handshake_part2_nokeygen(
                &relay_keypair_y, relay_state, verification,
                sizeof(verification), server_message, sizeof(server_message),
                &server_handshake, &server_handshake_len, server_keys,
                sizeof(server_keys), &server_export), OP_EQ, -1);
    tt_ptr_op(server_handshake, OP_EQ, NULL);
    tt_mem_op(&server_export, OP_EQ, &zero, sizeof(zero));
  }


 done:
  payment_profile_export_clear(&client_export);
  payment_profile_export_clear(&server_export);
  tor_free(onion_skin);
  tor_free(server_handshake);
  tor_free(mem_op_hex_tmp);
  ntor3_handshake_state_free(client_state);
  ntor3_server_handshake_state_free(relay_state);
  tor_free(cm);
  tor_free(sm);
  dimap_free(private_keys, NULL);
}

static void
test_ntor3_testvecs_payment(void *arg)
{
  (void)arg;
  test_ntor3_testvecs((void *)"payment");
}

static const char *
ntor_test_initial_payload(void)
{
  static char payload[782];
  uint8_t bytes[384]={0};
  for (size_t i=0;i<10;++i) bytes[64+i*32]=(uint8_t)(i+1);
  memcpy(payload,"eltor_payhash",13);
  base16_encode(payload+13,sizeof(payload)-13,(const char *)bytes,sizeof(bytes));
  for (char *p=payload+13;*p;++p) *p=TOR_TOLOWER(*p);
  return payload;
}

static void
run_full_handshake(circuit_params_t *serv_params_in,
                   circuit_params_t *client_params_out,
                   circuit_params_t *serv_params_out,
                   bool payment_requested)
{
  extend_info_t info = {0};
  uint8_t onionskin[CELL_PAYLOAD_SIZE];
  int onionskin_len = 0;
  int reply_len = 0;
  onion_handshake_state_t handshake_state = {0};
  server_onion_keys_t server_keys = {0};
  curve25519_keypair_t relay_onion_key;
  uint8_t serv_reply[CELL_PAYLOAD_SIZE];
  uint8_t serv_keys[100];
  uint8_t rend_nonce[DIGEST_LEN];
  uint8_t client_keys[CELL_PAYLOAD_SIZE];
  uint8_t rend_auth[DIGEST_LEN];
  payment_profile_export_t client_export = {0}, server_export = {0};

  info.supports_ntor_v3 = true;
  info.payment_free_v1 = true;
  info.use_congestion_control = congestion_control_enabled();
  serv_params_in->eltor_resource_eligible=payment_requested;

  unhex(relay_onion_key.seckey.secret_key,
        "4051daa5921cfa2a1c27b08451324919538e79e788a81b38cbed097a5dff454a");
  unhex(relay_onion_key.pubkey.public_key,
        "f8307a2bc1870b00b828bb74dbb8fd88e632a6375ab3bcd1ae706aaa8b6cdd1d");

  memcpy(&info.curve25519_onion_key,
         &relay_onion_key.pubkey, sizeof(info.curve25519_onion_key));
  unhex(info.ed_identity.pubkey,
        "9fad2af287ef942632833d21f946c6260c33fae6172b60006e86e4a6911753a2");

  memcpy(&server_keys.my_ed_identity, &info.ed_identity,
         sizeof(server_keys.my_ed_identity));

  dimap_add_entry(&server_keys.curve25519_key_map,
                  relay_onion_key.pubkey.public_key,
                  &relay_onion_key);

  onionskin_len = onion_skin_create(ONION_HANDSHAKE_TYPE_NTOR_V3, &info,
                    &handshake_state, onionskin,
                    sizeof(onionskin),
                    payment_requested ? ntor_test_initial_payload() : NULL,
                    payment_requested);
  tt_int_op(onionskin_len, OP_NE, -1);

  server_keys.junk_keypair = &handshake_state.u.ntor3->client_keypair;

  uint64_t test_p_circ = 999;
  uint64_t test_n_circ = 888;
  size_t serv_keylen = sizeof(serv_keys);
  size_t client_keylen = sizeof(serv_keys);
  reply_len = onion_skin_server_handshake(ONION_HANDSHAKE_TYPE_NTOR_V3,
                              onionskin, onionskin_len,
                              &server_keys, serv_params_in,
                              serv_reply, sizeof(serv_reply),
                              serv_keys, &serv_keylen,
                              rend_nonce, serv_params_out,
                              &test_p_circ, &test_n_circ,
                              payment_requested, &server_export, NULL);
  tt_int_op(reply_len, OP_NE, -1);

  tt_int_op(onion_skin_client_handshake(ONION_HANDSHAKE_TYPE_NTOR_V3,
                              &handshake_state,
                              serv_reply, reply_len,
                              client_keys, &client_keylen,
                              rend_auth, client_params_out,
                              NULL, &client_export), OP_EQ, 0);
  tt_int_op(client_export.valid, OP_EQ, payment_requested);
  tt_int_op(server_export.valid, OP_EQ, payment_requested);
  tt_mem_op(&client_export.keys, OP_EQ, &server_export.keys,
            sizeof(client_export.keys));
  tt_size_op(client_keylen, OP_EQ, serv_keylen);
  tt_mem_op(client_keys, OP_EQ, serv_keys, serv_keylen);
  tt_mem_op(rend_auth, OP_EQ, rend_nonce, DIGEST_LEN);

 done:
  payment_profile_export_clear(&client_export);
  payment_profile_export_clear(&server_export);
  dimap_free(server_keys.curve25519_key_map, NULL);
  ntor3_handshake_state_free(handshake_state.u.ntor3);

  return;
}

/**
 * Test congestion control negotiation logic.
 *
 * This tests that congestion control is only enabled when both
 * client and server agree, via consensus param or torrc.
 *
 * It also tests that when they agree, they agree on the server's
 * version of sendme_inc.
 */
static void
test_ntor3_handshake(void *arg)
{
  (void)arg;
  circuit_params_t client_params, serv_params, serv_ns_params;

  serv_ns_params.sendme_inc_cells = congestion_control_sendme_inc();

  /* client off, serv off -> off */
  congestion_control_set_cc_disabled();
  serv_ns_params.cc_enabled = 0;
  run_full_handshake(&serv_ns_params, &client_params, &serv_params, false);
  tt_int_op(client_params.cc_enabled, OP_EQ, 0);
  tt_int_op(serv_params.cc_enabled, OP_EQ, 0);

  /* client off, serv on -> off */
  congestion_control_set_cc_disabled();
  serv_ns_params.cc_enabled = 1;
  run_full_handshake(&serv_ns_params, &client_params, &serv_params, false);
  tt_int_op(client_params.cc_enabled, OP_EQ, 0);
  tt_int_op(serv_params.cc_enabled, OP_EQ, 0);

  /* client off + param, serv on -> on */
  serv_ns_params.cc_enabled = 1;
  get_options_mutable()->AlwaysCongestionControl = 1;
  run_full_handshake(&serv_ns_params, &client_params, &serv_params, false);
  tt_int_op(client_params.cc_enabled, OP_EQ, 1);
  tt_int_op(serv_params.cc_enabled, OP_EQ, 1);

#if 0
  // No longer supported: If the client asks for CC,
  // the server may not decline.

  /* client on, serv off -> off */
  serv_ns_params.cc_enabled = 0;
  congestion_control_set_cc_enabled();
  run_full_handshake(&serv_ns_params, &client_params, &serv_params, false);
  tt_int_op(client_params.cc_enabled, OP_EQ, 0);
  tt_int_op(serv_params.cc_enabled, OP_EQ, 0);
#endif

  /* client on, serv on -> on */
  serv_ns_params.cc_enabled = 1;
  run_full_handshake(&serv_ns_params, &client_params, &serv_params, false);
  tt_int_op(client_params.cc_enabled, OP_EQ, 1);
  tt_int_op(serv_params.cc_enabled, OP_EQ, 1);

  /* client on, serv on, sendme_inc diff -> serv sendme_inc */
  serv_ns_params.cc_enabled = 1;
  serv_ns_params.sendme_inc_cells += 1;
  run_full_handshake(&serv_ns_params, &client_params, &serv_params, false);
  tt_int_op(client_params.cc_enabled, OP_EQ, 1);
  tt_int_op(serv_params.cc_enabled, OP_EQ, 1);
  tt_int_op(serv_params.sendme_inc_cells, OP_EQ,
            client_params.sendme_inc_cells);
  tt_int_op(client_params.sendme_inc_cells, OP_EQ,
            serv_ns_params.sendme_inc_cells);
  tt_int_op(client_params.sendme_inc_cells, OP_NE,
            congestion_control_sendme_inc());

 done:
  return;
}

static void
test_ntor3_payment_export(void *arg)
{
  (void)arg;
  circuit_params_t ns_params = {0}, client_params, server_params;
  congestion_control_set_cc_disabled();
  run_full_handshake(&ns_params, &client_params, &server_params, true);
}

/* Authentication can succeed while parameter parsing subsequently fails.
 * Dedicated payment output must remain unavailable in both failure orders. */
static void
test_ntor3_payment_negotiation_failure(void *arg)
{
  (void)arg;
  ntor3_handshake_state_t *bad_client = NULL;
  ntor3_server_handshake_state_t *server_state = NULL;
  onion_handshake_state_t client_state = {0};
  uint8_t *skin = NULL, *client_msg = NULL, *reply = NULL;
  size_t skin_len = 0, client_msg_len = 0, reply_len = 0;
  payment_profile_export_t result = {0}, zero = {0};
  extend_info_t info = {0};
  server_onion_keys_t server = {0};
  circuit_params_t ns_params = {0}, negotiated;
  ns_params.eltor_resource_eligible=true;
  curve25519_keypair_t relay_key;
  uint8_t keys[100], nonce[DIGEST_LEN], reply_buffer[CELL_PAYLOAD_SIZE];
  uint8_t skin_buffer[CELL_PAYLOAD_SIZE], malformed = 255;
  const uint8_t verification[] = "circuit extend";
  size_t keylen = sizeof(keys);
  congestion_control_set_cc_disabled();
  tt_int_op(curve25519_keypair_generate(&relay_key, 0), OP_EQ, 0);
  memset(info.ed_identity.pubkey, 0x4a, 32);
  info.curve25519_onion_key = relay_key.pubkey;
  info.supports_ntor_v3 = true;
  info.payment_free_v1 = true;
  server.my_ed_identity = info.ed_identity;
  server.junk_keypair = &relay_key;
  dimap_add_entry(&server.curve25519_key_map,
                  relay_key.pubkey.public_key, &relay_key);

  /* A MAC-valid client message with malformed parameter extensions. */
  tt_int_op(onion_skin_ntor3_create(&info.ed_identity, &relay_key.pubkey,
                 verification, sizeof(verification)-1, &malformed, 1,
                 &bad_client, &skin, &skin_len, true), OP_EQ, 0);
  memset(&result, 0xff, sizeof(result));
  tt_int_op(onion_skin_server_handshake(ONION_HANDSHAKE_TYPE_NTOR_V3,
               skin, skin_len, &server, &ns_params, reply_buffer,
               sizeof(reply_buffer), keys, &keylen, nonce, &negotiated,
               NULL, NULL, true, &result, NULL), OP_EQ, -1);
  tt_mem_op(&result, OP_EQ, &zero, sizeof(zero));

  int len = onion_skin_create(ONION_HANDSHAKE_TYPE_NTOR_V3, &info,
                    &client_state, skin_buffer, sizeof(skin_buffer),
                    ntor_test_initial_payload(), true);
  tt_int_op(len, OP_GT, 0);
  tt_int_op(onion_skin_ntor3_server_handshake_part1(
                 server.curve25519_key_map, &relay_key, &info.ed_identity,
                 skin_buffer, len, verification, sizeof(verification)-1,
                 &client_msg, &client_msg_len, &server_state,
                 NULL, NULL, true), OP_EQ, 0);
  tt_int_op(onion_skin_ntor3_server_handshake_part2(server_state,
                 verification, sizeof(verification)-1, &malformed, 1,
                 &reply, &reply_len, keys, sizeof(keys), &result), OP_EQ, 0);
  tt_assert(result.valid);
  /* The ntor cryptography is valid, but the server's parameters are not. */
  memset(&result, 0xff, sizeof(result));
  keylen = sizeof(keys);
  tt_int_op(onion_skin_client_handshake(ONION_HANDSHAKE_TYPE_NTOR_V3,
                 &client_state, reply, reply_len, keys, &keylen, nonce,
                 &negotiated, NULL, &result), OP_EQ, -1);
  tt_mem_op(&result, OP_EQ, &zero, sizeof(zero));

 done:
  payment_profile_export_clear(&result);
  ntor3_handshake_state_free(bad_client);
  ntor3_server_handshake_state_free(server_state);
  onion_handshake_state_release(&client_state);
  dimap_free(server.curve25519_key_map, NULL);
  tor_free(skin);
  tor_free(client_msg);
  tor_free(reply);
}

/* Exercise the actual origin finisher, including ownership transfer and
 * transcript release, rather than only copying a result in a test. */
static void
test_ntor3_payment_origin_install(void *arg)
{
  (void)arg;
  origin_circuit_t *origin = NULL;
  or_connection_t resource_conn={0};
  timers_initialize();
  server_onion_keys_t server = {0};
  payment_profile_export_t result = {0};
  curve25519_keypair_t relay_key;
  extend_info_t info = {0};
  circuit_params_t ns_params = {0}, negotiated;
  ns_params.eltor_resource_eligible=true;
  uint8_t skin[CELL_PAYLOAD_SIZE], keys[100], nonce[DIGEST_LEN];
  created_cell_t reply = {0};
  congestion_control_set_cc_disabled();
  get_options_mutable()->AlwaysCongestionControl = 0;
  tt_int_op(curve25519_keypair_generate(&relay_key, 0), OP_EQ, 0);
  memset(info.ed_identity.pubkey, 0x4b, 32);
  info.curve25519_onion_key = relay_key.pubkey;
  info.supports_ntor_v3 = true;
  info.payment_free_v1 = true;
  server.my_ed_identity = info.ed_identity;
  server.junk_keypair = &relay_key;
  dimap_add_entry(&server.curve25519_key_map,
                  relay_key.pubkey.public_key, &relay_key);
  origin = origin_circuit_new();
  origin->base_.purpose = CIRCUIT_PURPOSE_CONTROLLER;
  origin->build_state = tor_malloc_zero(sizeof(*origin->build_state));
  origin->build_state->desired_path_len = 1;
  origin->any_hop_from_controller = 1;
  tt_int_op(cpath_append_hop(&origin->cpath, &info), OP_EQ, 0);
  crypt_path_t *hop = origin->cpath;
  tt_assert(!hop->payment_export_requested);
  tt_ptr_op(hop->payment_keys, OP_EQ, NULL);
  /* Explicit opt in to authenticated resource negotiation for this test. */
  hop->payment_export_requested = true;
  tt_int_op(free_capacity_circuit_prepare(TO_CIRCUIT(origin),&resource_conn),OP_EQ,0);
  int skin_len = onion_skin_create(ONION_HANDSHAKE_TYPE_NTOR_V3,
                    hop->extend_info, &hop->handshake_state,
                    skin, sizeof(skin), ntor_test_initial_payload(),
                    hop->payment_export_requested);
  tt_int_op(skin_len, OP_GT, 0);
  hop->state = CPATH_STATE_AWAITING_KEYS;
  size_t keylen = sizeof(keys);
  int reply_len = onion_skin_server_handshake(ONION_HANDSHAKE_TYPE_NTOR_V3,
                    skin, skin_len, &server, &ns_params,
                    reply.reply, sizeof(reply.reply), keys, &keylen,
                    nonce, &negotiated, NULL, NULL, true, &result, NULL);
  tt_int_op(reply_len, OP_GT, 0);
  tt_assert(result.valid);
  reply.cell_type = CELL_CREATED2;
  reply.handshake_len = reply_len;
  tt_int_op(circuit_finish_handshake(origin, &reply), OP_EQ, 0);
  tt_int_op(hop->state, OP_EQ, CPATH_STATE_OPEN);
  tt_assert(hop->payment_keys);
  tt_mem_op(hop->payment_keys, OP_EQ, &result.keys, sizeof(result.keys));
  tt_ptr_op(hop->handshake_state.u.ntor3, OP_EQ, NULL);
  tt_assert(!hop->handshake_state.payment_export_requested);
  circuit_mark_for_close(TO_CIRCUIT(origin), END_CIRC_REASON_DESTROYED);
  tt_ptr_op(hop->payment_keys, OP_EQ, NULL);
 done:
  payment_profile_export_clear(&result);
  dimap_free(server.curve25519_key_map, NULL);
  circuit_free_all();
  free_capacity_connection_free(&resource_conn);
  (void)payment_resources_free_all();
  timers_shutdown();
}

/* MAC-valid resource requests must still fail on missing frozen admission or
 * a noncanonical initial suffix, without publishing any partial output. */
static void
test_ntor3_resource_rejections(void *arg)
{
  (void)arg;
  curve25519_keypair_t relay_key;
  server_onion_keys_t server={0};
  ntor3_handshake_state_t *client=NULL;
  payment_profile_export_t result,zero={0};
  payment_initial_material_t material,zero_material={0};
  circuit_params_t params,zero_params={0},ns={0};
  uint8_t *skin=NULL;
  size_t skin_len=0;
  uint8_t plaintext[5+781],reply_buffer[CELL_PAYLOAD_SIZE];
  uint8_t keys[MAX_RELAY_KEY_MATERIAL_LEN],nonce[DIGEST_LEN];
  const uint8_t verification[]="circuit extend";
  congestion_control_set_cc_disabled();
  tt_int_op(curve25519_keypair_generate(&relay_key,0),OP_EQ,0);
  memset(server.my_ed_identity.pubkey,0x47,32);
  server.junk_keypair=&relay_key;
  dimap_add_entry(&server.curve25519_key_map,
                 relay_key.pubkey.public_key,&relay_key);
  for (unsigned mode=0;mode<3;++mode) {
    memcpy(plaintext,"\x01\xe0\x02\x01\x01",5);
    memcpy(plaintext+5,ntor_test_initial_payload(),781);
    ns.eltor_resource_eligible=mode!=0;
    if (mode==1) plaintext[5+13]='A'; /* forbidden upper-case hex */
    size_t n=sizeof(plaintext)-(mode==2); /* truncated authenticated suffix */
    tt_int_op(onion_skin_ntor3_create(&server.my_ed_identity,&relay_key.pubkey,
          verification,sizeof(verification)-1,plaintext,n,&client,&skin,&skin_len,
          true),OP_EQ,0);
    memset(&result,0xff,sizeof(result));
    memset(&material,0xff,sizeof(material));
    memset(&params,0xff,sizeof(params));
    size_t keylen=sizeof(keys);
    tt_int_op(onion_skin_server_handshake(ONION_HANDSHAKE_TYPE_NTOR_V3,
          skin,skin_len,&server,&ns,reply_buffer,sizeof(reply_buffer),keys,&keylen,
          nonce,&params,NULL,NULL,true,&result,&material),OP_EQ,-1);
    tt_mem_op(&result,OP_EQ,&zero,sizeof(zero));
    tt_mem_op(&material,OP_EQ,&zero_material,sizeof(zero_material));
    tt_mem_op(&params,OP_EQ,&zero_params,sizeof(zero_params));
    ntor3_handshake_state_free(client); tor_free(skin);
  }
 done:
  ntor3_handshake_state_free(client); tor_free(skin);
  dimap_free(server.curve25519_key_map,NULL);
  memwipe(plaintext,0,sizeof(plaintext));
}

/* The extending relay sees link specifiers and the child's encrypted ntor
 * message, never the child's hash/preimage/IDs in a second plaintext suffix. */
static void
test_ntor3_payment_extend_isolation(void *arg)
{
  (void)arg;
  curve25519_keypair_t relay_key;
  server_onion_keys_t server = {0};
  extend_info_t info = {0};
  onion_handshake_state_t client = {0};
  payment_profile_export_t server_export = {0}, client_export = {0};
  payment_initial_material_t material = {0}, expected = {0};
  circuit_params_t ns = {0}, negotiated = {0}, client_params = {0};
  uint8_t raw[384], wire[RELAY_PAYLOAD_SIZE_MAX];
  uint8_t legacy[RELAY_PAYLOAD_SIZE_MAX], canonical[RELAY_PAYLOAD_SIZE_MAX];
  uint8_t reply[CELL_PAYLOAD_SIZE], keys[100], client_keys[100];
  uint8_t nonce[DIGEST_LEN], client_nonce[DIGEST_LEN];
  char proof[782];
  uint16_t length = 0, previous_length = 0, legacy_length, canonical_length;
  uint8_t command = 0, legacy_command, canonical_command;
  extend_cell_t cell = {0}, parsed = {0};
  congestion_control_set_cc_disabled();
  get_options_mutable()->AlwaysCongestionControl = 0;
  tt_int_op(curve25519_keypair_generate(&relay_key, 0), OP_EQ, 0);
  memset(info.ed_identity.pubkey, 0x49, 32);
  info.curve25519_onion_key = relay_key.pubkey;
  info.supports_ntor_v3 = info.payment_free_v1 = true;
  server.my_ed_identity = info.ed_identity;
  server.junk_keypair = &relay_key;
  dimap_add_entry(&server.curve25519_key_map,
                 relay_key.pubkey.public_key, &relay_key);
  ns.eltor_resource_eligible = true;
  for (unsigned paid = 0; paid < 2; ++paid) {
    memset(raw, 0, sizeof(raw));
    memset(raw + 32, paid ? 0x72 : 0x61, 32);
    tt_int_op(crypto_digest256((char *)raw, (const char *)raw + 32, 32,
                               DIGEST_SHA256), OP_EQ, 0);
    for (unsigned i = 0; i < 10; ++i)
      memset(raw + 64 + i * 32, (int)(i + 1 + 16 * paid), 32);
    memcpy(proof, "eltor_payhash", 13);
    base16_encode(proof + 13, sizeof(proof) - 13,
                  (const char *)raw, sizeof(raw));
    for (char *p = proof + 13; *p; ++p) *p = TOR_TOLOWER(*p);
    tt_int_op(payment_initial_parse(&expected, (const uint8_t *)proof,
                                    strlen(proof)), OP_EQ, 0);
    info.payment_start_v1 = info.payment_renew_v1 = paid != 0;
    memset(&cell, 0, sizeof(cell));
    cell.cell_type = RELAY_COMMAND_EXTEND2;
    cell.create_cell.cell_type = CELL_CREATE2;
    cell.create_cell.handshake_type = ONION_HANDSHAKE_TYPE_NTOR_V3;
    memset(cell.node_id, 0x35, sizeof(cell.node_id));
    tt_int_op(tor_addr_parse(&cell.orport_ipv4.addr, "127.0.0.1"),
              OP_EQ, AF_INET);
    cell.orport_ipv4.port = 9001;
    int skin_len = onion_skin_create(ONION_HANDSHAKE_TYPE_NTOR_V3, &info,
        &client, cell.create_cell.onionskin,
        sizeof(cell.create_cell.onionskin), proof, true);
    tt_int_op(skin_len, OP_GT, 0);
    cell.create_cell.handshake_len = skin_len;
    tt_int_op(extend_cell_format_foundation(&command, &length, wire, &cell),
              OP_EQ, 0);
    tt_int_op(extend_cell_format(&canonical_command, &canonical_length,
                                 canonical, &cell, NULL), OP_EQ, 0);
    tt_int_op(command, OP_EQ, canonical_command);
    tt_int_op(length, OP_EQ, canonical_length);
    tt_mem_op(wire, OP_EQ, canonical, length);
    tt_ptr_op(tor_memmem(wire, length, "eltor_payhash", 13), OP_EQ, NULL);
    for (unsigned i = 0; i < 12; ++i)
      tt_ptr_op(tor_memmem(wire, length, proof + 13 + i * 64, 64),
                OP_EQ, NULL);
    if (paid) tt_int_op(length, OP_EQ, previous_length);
    previous_length = length;
    /* Explicit profile-off legacy encoding remains available, including its
     * former suffix. This control reproduces the original exposure. */
    tt_int_op(extend_cell_format(&legacy_command, &legacy_length, legacy,
                                 &cell, proof), OP_EQ, 0);
    tt_int_op(legacy_length, OP_EQ, length + strlen(proof));
    tt_mem_op(legacy + length, OP_EQ, proof, strlen(proof));
    tt_int_op(extend_cell_parse(&parsed, command, wire, length), OP_EQ, 0);
    tt_int_op(parsed.create_cell.handshake_len, OP_EQ, skin_len);
    tt_mem_op(parsed.create_cell.onionskin, OP_EQ,
              cell.create_cell.onionskin, skin_len);
    size_t keylen = sizeof(keys);
    int reply_len = onion_skin_server_handshake(ONION_HANDSHAKE_TYPE_NTOR_V3,
        parsed.create_cell.onionskin, parsed.create_cell.handshake_len,
        &server, &ns, reply, sizeof(reply), keys, &keylen, nonce, &negotiated,
        NULL, NULL, true, &server_export, &material);
    tt_int_op(reply_len, OP_GT, 0);
    tt_assert(negotiated.eltor_resource_admitted && server_export.valid);
    tt_assert(material.valid);
    tt_mem_op(material.fee_hash, OP_EQ, expected.fee_hash, 32);
    tt_mem_op(material.ids, OP_EQ, expected.ids, sizeof(expected.ids));
    size_t client_keylen = sizeof(client_keys);
    client_params = client.chosen_params;
    tt_int_op(onion_skin_client_handshake(ONION_HANDSHAKE_TYPE_NTOR_V3,
        &client, reply, reply_len, client_keys, &client_keylen, client_nonce,
        &client_params, NULL, &client_export), OP_EQ, 0);
    tt_assert(client_params.eltor_resource_admitted && client_export.valid);
    tt_int_op(keylen, OP_EQ, client_keylen);
    tt_mem_op(keys, OP_EQ, client_keys, keylen);
    tt_mem_op(&server_export.keys, OP_EQ, &client_export.keys,
              sizeof(server_export.keys));
    onion_handshake_state_release(&client);
    payment_profile_export_clear(&server_export);
    payment_profile_export_clear(&client_export);
    payment_initial_clear(&material);
    payment_initial_clear(&expected);
  }
  cell.create_cell.handshake_type = ONION_HANDSHAKE_TYPE_NTOR;
  tt_int_op(extend_cell_format_foundation(&command, &length, wire, &cell),
            OP_EQ, -1);
 done:
  onion_handshake_state_release(&client);
  payment_profile_export_clear(&server_export);
  payment_profile_export_clear(&client_export);
  payment_initial_clear(&material);
  payment_initial_clear(&expected);
  dimap_free(server.curve25519_key_map, NULL);
  memwipe(raw, 0, sizeof(raw));
  memwipe(proof, 0, sizeof(proof));
}

static unsigned legacy_payment_events;
static char *legacy_payment_event;
static void
capture_legacy_payment_event(uint16_t event, char *message)
{
  (void)event;
  if (strstr(message, "650 EVENT_PAYMENT_ID_HASH_RECEIVED ")) {
    ++legacy_payment_events;
    tor_free(legacy_payment_event);
    legacy_payment_event = tor_strdup(message);
  }
  tor_free(message);
}

/* A missing resource field cannot route enabled-mode bootstrap proof material
 * into the profile-off legacy observer. The old observer remains unchanged
 * when the worker's immutable eligibility input says foundation is disabled. */
static void
test_ntor3_legacy_event_isolation(void *arg)
{
  (void)arg;
  curve25519_keypair_t relay_key;
  server_onion_keys_t server = {0};
  extend_info_t info = {0};
  onion_handshake_state_t client = {0};
  payment_profile_export_t server_export = {0}, client_export = {0};
  payment_initial_material_t material = {0};
  circuit_params_t ns = {0}, negotiated = {0}, client_params = {0};
  uint8_t skin[CELL_PAYLOAD_SIZE], reply[CELL_PAYLOAD_SIZE];
  uint8_t keys[100], client_keys[100], nonce[DIGEST_LEN];
  uint64_t previous_id = 12, next_id = 13;
  congestion_control_set_cc_disabled();
  get_options_mutable()->AlwaysCongestionControl = 0;
  MOCK(queue_control_event_string, capture_legacy_payment_event);
  tt_int_op(curve25519_keypair_generate(&relay_key, 0), OP_EQ, 0);
  memset(info.ed_identity.pubkey, 0x4c, 32);
  info.curve25519_onion_key = relay_key.pubkey;
  info.supports_ntor_v3 = info.payment_free_v1 = true;
  server.my_ed_identity = info.ed_identity;
  server.junk_keypair = &relay_key;
  dimap_add_entry(&server.curve25519_key_map,
                 relay_key.pubkey.public_key, &relay_key);
  for (unsigned mode = 0; mode < 3; ++mode) {
    bool enabled = mode != 0, requested = mode == 2;
    legacy_payment_events = 0;
    tor_free(legacy_payment_event);
    ns.eltor_resource_eligible = enabled;
    int skin_len = onion_skin_create(ONION_HANDSHAKE_TYPE_NTOR_V3, &info,
        &client, skin, sizeof(skin), ntor_test_initial_payload(), requested);
    tt_int_op(skin_len, OP_GT, 0);
    size_t keylen = sizeof(keys);
    int reply_len = onion_skin_server_handshake(ONION_HANDSHAKE_TYPE_NTOR_V3,
        skin, skin_len, &server, &ns, reply, sizeof(reply), keys, &keylen,
        nonce, &negotiated, &previous_id, &next_id, enabled,
        &server_export, &material);
    tt_int_op(reply_len, OP_GT, 0);
    tt_int_op(legacy_payment_events, OP_EQ, enabled ? 0 : 1);
    if (!enabled) {
      tt_assert(legacy_payment_event);
      tt_assert(strstr(legacy_payment_event, "P_CIRC_ID=12 N_CIRC_ID=13"));
      tt_assert(strstr(legacy_payment_event, ntor_test_initial_payload() + 13));
    } else {
      tt_ptr_op(legacy_payment_event, OP_EQ, NULL);
    }
    tt_int_op(negotiated.eltor_resource_admitted, OP_EQ, requested);
    tt_int_op(material.valid, OP_EQ, requested);
    tt_int_op(server_export.valid, OP_EQ, requested);
    size_t client_keylen = sizeof(client_keys);
    client_params = client.chosen_params;
    tt_int_op(onion_skin_client_handshake(ONION_HANDSHAKE_TYPE_NTOR_V3,
        &client, reply, reply_len, client_keys, &client_keylen, nonce,
        &client_params, NULL, &client_export), OP_EQ, 0);
    tt_int_op(keylen, OP_EQ, client_keylen);
    tt_mem_op(keys, OP_EQ, client_keys, keylen);
    tt_int_op(client_export.valid, OP_EQ, requested);
    onion_handshake_state_release(&client);
    payment_profile_export_clear(&server_export);
    payment_profile_export_clear(&client_export);
    payment_initial_clear(&material);
  }
 done:
  UNMOCK(queue_control_event_string);
  tor_free(legacy_payment_event);
  onion_handshake_state_release(&client);
  payment_profile_export_clear(&server_export);
  payment_profile_export_clear(&client_export);
  payment_initial_clear(&material);
  dimap_free(server.curve25519_key_map, NULL);
}

struct testcase_t ntor_v3_tests[] = {
  { "testvecs", test_ntor3_testvecs, 0, NULL, NULL, },
  { "testvecs_payment_export", test_ntor3_testvecs_payment,
    0, NULL, NULL, },
  { "resource_rejections", test_ntor3_resource_rejections,TT_FORK,NULL,NULL },
  { "payment_extend_isolation", test_ntor3_payment_extend_isolation,
    TT_FORK, NULL, NULL },
  { "legacy_event_isolation", test_ntor3_legacy_event_isolation,
    TT_FORK, NULL, NULL },
  { "payment_export", test_ntor3_payment_export, TT_FORK, NULL, NULL, },
  { "payment_origin_install", test_ntor3_payment_origin_install,
    TT_FORK, &helper_pubsub_setup, NULL, },
  { "payment_negotiation_failure", test_ntor3_payment_negotiation_failure,
    TT_FORK, NULL, NULL, },
  { "handshake_negtotiation", test_ntor3_handshake, 0, NULL, NULL, },
  END_OF_TESTCASES,
};
