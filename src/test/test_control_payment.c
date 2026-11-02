/* Copyright (c) 2026, The El Tor Project. */
/* See LICENSE for licensing information. */
#define CONTROL_EVENTS_PRIVATE
#include "orconfig.h"
#include "core/or/or.h"
#include "feature/control/control_payment.h"
#include "feature/payment/payment_resources.h"
#include "core/mainloop/connection.h"
#include "lib/buf/buffers.h"
#include "feature/control/control.h"
#include "feature/control/control_events.h"
#include "feature/control/control_proto.h"
#include "feature/control/control_connection_st.h"
#include "core/or/circuit_st.h"
#include "core/or/origin_circuit_st.h"
#include "core/or/or_circuit_st.h"
#include "core/or/circuitlist.h"
#include "core/or/relay.h"
#include "core/or/relay_msg_st.h"
#include "lib/evloop/timers.h"
#include "lib/time/compat_time.h"
#include "test/test.h"

#define HEX16 "11111111111111111111111111111111"
#define HEX32 HEX16 HEX16
#define ZERO16 "00000000000000000000000000000000"
#define ZERO32 ZERO16 ZERO16

static void
test_control_payment_parser(void *arg)
{
  control_payment_request_t request;
  const char *valid = "ELTOR_PAYMENT_AUTHORIZE 1 " HEX16 " " HEX16 " "
    HEX16 " 10 25 " HEX32 " " HEX32 "\r\n";
  const char *invalid[] = {
    "ELTOR_CIRCUIT_BIND 1 0\r\n",
    "ELTOR_CIRCUIT_BIND 1 01\r\n",
    "ELTOR_CIRCUIT_BIND 1 +1\r\n",
    "ELTOR_CIRCUIT_BIND 1 4294967296\r\n",
    "ELTOR_CIRCUIT_BIND 1 1\n",
    "ELTOR_CIRCUIT_BIND 1 1 \r\n",
    "ELTOR_CIRCUIT_BIND  1 1\r\n",
    "ELTOR_CIRCUIT_BIND\t1 1\r\n",
    "ELTOR_CIRCUIT_BIND 1 1 EXTRA\r\n",
    "eltor_circuit_bind 1 1\r\n",
    "ELTOR_CIRCUIT_BIND 2 1\r\n",
    "ELTOR_CIRCUIT_BIND 1 \"1\"\r\n",
    "ELTOR_PAYMENT_LIST 1 " HEX16 " -\r\n",
    "ELTOR_PAYMENT_LIST 1 - " HEX16 "\r\n",
    "ELTOR_INITIAL_GET 1 " HEX16 " " HEX16 " 17 -\r\n",
    "ELTOR_INITIAL_GET 1 " HEX16 " " HEX16 " 0 -\r\n",
    "ELTOR_INITIAL_GET 1 A1111111111111111111111111111111 " HEX16 " 1 -\r\n",
    "ELTOR_PAYMENT_ADMISSION_DECIDE 1 " HEX16 " " HEX16 " 0 " HEX32
      " " ZERO16 " RESERVED\r\n",
    "ELTOR_PAYMENT_ADMISSION_DECIDE 1 " HEX16 " " HEX16 " 0 " HEX32
      " " HEX16 " authorized\r\n",
    "ELTOR_PAYMENT_AUTHORIZE 1 " HEX16 " " HEX16 " " HEX16
      " 1 1 " ZERO32 " " HEX32 "\r\n",
    "ELTOR_PAYMENT_AUTHORIZE 1 " HEX16 " " HEX16 " " HEX16
      " 1 0 " HEX32 " " HEX32 "\r\n",
    "ELTOR_PAYMENT_AUTHORIZE 1 " HEX16 " " HEX16 " " HEX16
      " 18446744073709551616 1 " HEX32 " " HEX32 "\r\n"
  };
  (void)arg;
  tt_int_op(control_payment_parse(valid, strlen(valid), &request), OP_EQ, 0);
  tt_uint_op(request.command, OP_EQ, CONTROL_PAYMENT_AUTHORIZE);
  tt_u64_op(request.round, OP_EQ, 10);
  tt_u64_op(request.amount_msat, OP_EQ, 25);
  for (unsigned i = 0; i < ARRAY_LENGTH(invalid); ++i) {
    memset(&request, 0xff, sizeof(request));
    tt_int_op(control_payment_parse(invalid[i], strlen(invalid[i]), &request),
              OP_EQ, -1);
    tt_uint_op(request.command, OP_EQ, 0);
  }
  valid = "ELTOR_PAYMENT_LIST 1 - -\r\n";
  tt_int_op(control_payment_parse(valid, strlen(valid), &request), OP_EQ, 0);
  tt_assert(request.first_page);
  valid = "ELTOR_INITIAL_GET 1 " HEX16 " " HEX16 " 1 -\r\n";
  tt_int_op(control_payment_parse(valid, strlen(valid), &request), OP_EQ, 0);
  tt_assert(request.no_operation);
  valid = "ELTOR_PAYMENT_AUTHORIZE 1 " HEX16 " " HEX16 " " HEX16
    " 0 0 " ZERO32 " " HEX32 "\r\n";
  tt_int_op(control_payment_parse(valid, strlen(valid), &request), OP_EQ, 0);
 done:
  ;
}

static void
test_control_payment_record_digest(void *arg)
{
  uint8_t instance[16], handle[16], decision[16], hash[32], terms[32], initial[32];
  uint8_t digest[32], expected[32];
  (void)arg;
  memset(instance, 1, 16);
  memset(handle, 2, 16);
  memset(decision, 3, 16);
  memset(hash, 4, 32);
  memset(terms, 5, 32);
  memset(initial, 6, 32);
  /* Independent SHA256 fixture over the specified 161 network-order bytes. */
  tt_int_op(base16_decode((char *)expected, 32,
    "57422a95defd2921b5f209938cdf22f9ea93a5829adb3fce662d290e90744f07", 64),
    OP_EQ, 32);
  tt_int_op(control_payment_record_digest(digest, instance, handle, decision,
      UINT64_C(0x0102030405060708), 777, hash, terms, initial), OP_EQ, 0);
  tt_mem_op(digest, OP_EQ, expected, 32);
 done:
  ;
}

static void
test_control_payment_authority(void *arg)
{
  control_connection_t conn;
  (void)arg;
  memset(&conn, 0, sizeof(conn));
  conn.base_.state = CONTROL_CONN_STATE_OPEN;
  conn.base_.socket_family = AF_INET;
  tt_int_op(tor_addr_parse(&conn.base_.addr, "127.0.0.1"), OP_EQ, AF_INET);
  tt_assert(control_payment_authority(&conn));
  conn.base_.state = CONTROL_CONN_STATE_NEEDAUTH;
  tt_assert(!control_payment_authority(&conn));
  conn.base_.state = CONTROL_CONN_STATE_OPEN;
  tt_int_op(tor_addr_parse(&conn.base_.addr, "192.0.2.1"), OP_EQ, AF_INET);
  tt_assert(!control_payment_authority(&conn));
  conn.base_.socket_family = AF_UNSPEC;
  tor_addr_make_unspec(&conn.base_.addr);
  tt_assert(!control_payment_authority(&conn));
  conn.payment_local_fd = true;
  tt_assert(control_payment_authority(&conn));
  conn.base_.marked_for_close = 1;
  tt_assert(!control_payment_authority(&conn));
 done:
  ;
}

static smartlist_t *payment_replies;
static void
capture_payment_reply(control_connection_t *conn, int code, int separator,
                       const char *body)
{
  char *line;
  (void)conn;
  tor_asprintf(&line, "%d%c%s\r\n", code, separator, body);
  smartlist_add(payment_replies, line);
}

static char *
collect_payment_replies(void)
{
  char *reply = smartlist_join_strings(payment_replies, "", 0, NULL);
  SMARTLIST_FOREACH(payment_replies, char *, item, tor_free(item));
  smartlist_clear(payment_replies);
  return reply;
}

static void
local_controller(control_connection_t *conn)
{
  memset(conn, 0, sizeof(*conn));
  conn->base_.magic = CONTROL_CONNECTION_MAGIC;
  conn->base_.type = CONN_TYPE_CONTROL;
  conn->base_.s = TOR_INVALID_SOCKET;
  conn->base_.conn_array_index = -1;
  conn->base_.closeable_list_index = -1;
  conn->base_.state = CONTROL_CONN_STATE_OPEN;
  conn->base_.socket_family = AF_UNSPEC;
  conn->payment_local_fd = true;
}

static void
test_control_payment_inventory(void *arg)
{
  origin_circuit_t *circuits = NULL;
  control_connection_t conn, other;
  char *page0 = NULL, *page1 = NULL, *reply = NULL, *command = NULL;
  char instance[33], cursor[33];
  uint8_t local_instance[16], handle[16];
  unsigned long long sequence;
  (void)arg;
  local_controller(&conn);
  local_controller(&other);
  payment_replies = smartlist_new();
  MOCK(control_write_reply, capture_payment_reply);
  monotime_enable_test_mocking();
  monotime_set_mock_time_nsec(INT64_C(1000000000));
  control_payment_init();
  circuits = tor_calloc(130, sizeof(*circuits));
  for (unsigned i = 0; i < 129; ++i) {
    circuits[i].base_.magic = ORIGIN_CIRCUIT_MAGIC;
    tt_int_op(control_payment_register(&circuits[i].base_,
      CONTROL_PAYMENT_ORIGIN, 3, true), OP_EQ, 0);
  }
  tt_int_op(control_payment_binding(&circuits[0].base_, local_instance, handle),
            OP_EQ, 0);
  command = tor_strdup("ELTOR_PAYMENT_LIST 1 - -\r\n");
  control_payment_handle_command(&conn, command, strlen(command));
  page0 = collect_payment_replies();
  tt_int_op(sscanf(page0, "250-ELTOR_PAYMENT_LIST 1 %32s %llu %32s",
                   instance, &sequence, cursor), OP_EQ, 3);
  tt_uint_op(sequence, OP_EQ, 129);
  tt_int_op(strcmp(cursor, "-"), OP_NE, 0);
  tt_int_op(smartlist_len(payment_replies), OP_EQ, 0);
  /* Changes after capture do not alter retry pages or their event sequence. */
  control_payment_circuit_closed(&circuits[0].base_);
  circuits[129].base_.magic = ORIGIN_CIRCUIT_MAGIC;
  tt_int_op(control_payment_register(&circuits[129].base_,
    CONTROL_PAYMENT_ORIGIN, 3, true), OP_EQ, 0);
  control_payment_handle_command(&conn, command, strlen(command));
  reply = collect_payment_replies();
  tt_str_op(reply, OP_EQ, page0);
  tor_free(reply);
  tor_free(command);
  tor_asprintf(&command, "ELTOR_PAYMENT_LIST 1 %s %s\r\n", instance, cursor);
  control_payment_handle_command(&conn, command, strlen(command));
  page1 = collect_payment_replies();
  tt_assert(strstr(page1, "250-CIRCUIT "));
  tt_assert(strstr(page1, "250 OK\r\n"));
  control_payment_handle_command(&conn, command, strlen(command));
  reply = collect_payment_replies();
  tt_str_op(reply, OP_EQ, page1);
  tor_free(reply);
  control_payment_handle_command(&other, command, strlen(command));
  reply = collect_payment_replies();
  tt_str_op(reply, OP_EQ, "552 UNKNOWN_CURSOR\r\n");
  tor_free(reply);
  monotime_set_mock_time_nsec(INT64_C(11000000000));
  control_payment_handle_command(&conn, command, strlen(command));
  reply = collect_payment_replies();
  tt_str_op(reply, OP_EQ, "552 UNKNOWN_CURSOR\r\n");
 done:
  UNMOCK(control_write_reply);
  control_payment_free_all();
  monotime_disable_test_mocking();
  tor_free(page0);
  tor_free(page1);
  tor_free(reply);
  tor_free(command);
  tor_free(circuits);
  if (payment_replies) {
    SMARTLIST_FOREACH(payment_replies, char *, item, tor_free(item));
    smartlist_free(payment_replies);
  }
}

static void
test_control_payment_query_and_snapshot_bounds(void *arg)
{
  control_connection_t conn[5];
  const char *command = "ELTOR_PAYMENT_LIST 1 - -\r\n";
  char *reply = NULL;
  (void)arg;
  for (unsigned i = 0; i < 5; ++i)
    local_controller(&conn[i]);
  payment_replies = smartlist_new();
  MOCK(control_write_reply, capture_payment_reply);
  monotime_enable_test_mocking();
  monotime_set_mock_time_nsec(INT64_C(1000000000));
  control_payment_init();
  for (unsigned i = 0; i < 4; ++i) {
    control_payment_handle_command(&conn[i], command, strlen(command));
    reply = collect_payment_replies();
    tt_assert(strstr(reply, "250-ELTOR_PAYMENT_LIST 1 "));
    tor_free(reply);
  }
  control_payment_handle_command(&conn[4], command, strlen(command));
  reply = collect_payment_replies();
  tt_str_op(reply, OP_EQ, "451 CAPACITY\r\n");
  tor_free(reply);
  control_payment_connection_closed(&conn[0]);
  control_payment_handle_command(&conn[4], command, strlen(command));
  reply = collect_payment_replies();
  tt_assert(strstr(reply, "250-ELTOR_PAYMENT_LIST 1 "));
  tor_free(reply);
  /* One exact sliding-window authority budget shared across connections. */
  for (unsigned i = 6; i < 64; ++i) {
    control_payment_handle_command(&conn[1], command, strlen(command));
    reply = collect_payment_replies();
    tt_assert(strstr(reply, "250-ELTOR_PAYMENT_LIST 1 "));
    tor_free(reply);
  }
  control_payment_handle_command(&conn[1], command, strlen(command));
  reply = collect_payment_replies();
  tt_str_op(reply, OP_EQ, "451 CAPACITY\r\n");
  tor_free(reply);
  monotime_set_mock_time_nsec(INT64_C(2000000000));
  control_payment_handle_command(&conn[1], command, strlen(command));
  reply = collect_payment_replies();
  tt_assert(strstr(reply, "250-ELTOR_PAYMENT_LIST 1 "));
 done:
  UNMOCK(control_write_reply);
  control_payment_free_all();
  monotime_disable_test_mocking();
  tor_free(reply);
  if (payment_replies) {
    SMARTLIST_FOREACH(payment_replies, char *, item, tor_free(item));
    smartlist_free(payment_replies);
  }
}

static unsigned payment_disconnects;
static void
capture_payment_output(const char *bytes, size_t len, connection_t *conn,
                        int zlib)
{
  (void)zlib;
  buf_add(conn->outbuf, bytes, len);
}

static void
capture_payment_disconnect(connection_t *conn, int line, const char *file)
{
  (void)line;
  (void)file;
  conn->marked_for_close = 1;
  ++payment_disconnects;
}

static void
test_control_payment_event_bound(void *arg)
{
  control_connection_t conn;
  const char *event = "650 ELTOR_PAYMENT_STATE 1 " HEX16 " 1 " HEX16
    " RELAY 1 COMMITTED\r\n";
  size_t queued;
  (void)arg;
  local_controller(&conn);
  conn.base_.outbuf = buf_new();
  payment_disconnects = 0;
  MOCK(connection_write_to_buf_impl_, capture_payment_output);
  MOCK(connection_mark_for_close_internal_, capture_payment_disconnect);
  for (unsigned i = 0; i < 1024; ++i)
    control_payment_queue_event(&conn, event);
  tt_uint_op(conn.payment_events_queued, OP_EQ, 1024);
  tt_uint_op(payment_disconnects, OP_EQ, 0);
  queued = buf_datalen(conn.base_.outbuf);
  tt_uint_op(queued, OP_EQ, 1024 * strlen(event));
  control_payment_queue_event(&conn, event);
  tt_uint_op(payment_disconnects, OP_EQ, 1);
  tt_uint_op(buf_datalen(conn.base_.outbuf), OP_EQ, queued);
  /* Only an actually drained connection can start another bounded batch. */
  buf_clear(conn.base_.outbuf);
  conn.base_.marked_for_close = 0;
  control_payment_finished_flushing(&conn);
  control_payment_queue_event(&conn, event);
  tt_uint_op(conn.payment_events_queued, OP_EQ, 1);
 done:
  UNMOCK(connection_write_to_buf_impl_);
  UNMOCK(connection_mark_for_close_internal_);
  control_payment_connection_closed(&conn);
  buf_free(conn.base_.outbuf);
  (void)payment_resources_free_all();
}

static unsigned payment_wire_replies;
static int
capture_payment_wire(streamid_t stream, circuit_t *circ, uint8_t command,
    const char *payload, size_t len, crypt_path_t *layer,
    const char *file, int line)
{
  (void)stream; (void)circ; (void)command; (void)payload;
  (void)len; (void)layer; (void)file; (void)line;
  ++payment_wire_replies;
  return 0;
}

static void
payment_test_hex(char *out, const uint8_t *data, size_t len)
{
  static const char digits[] = "0123456789abcdef";
  for (size_t i = 0; i < len; ++i) {
    out[2*i] = digits[data[i] >> 4];
    out[2*i+1] = digits[data[i] & 15];
  }
  out[2*len] = 0;
}

static void
test_control_payment_relay_bridge(void *arg)
{
  control_connection_t conn;
  or_circuit_t *circ = NULL;
  payment_profile_policy_t policy = {0};
  payment_profile_keys_t keys = {0};
  payment_profile_message_t commit = {0};
  payment_circuit_snapshot_t snapshot;
  relay_msg_t message = {0};
  uint8_t ids[10][32] = {{0}}, fee_hash[32], instance[16], handle[16];
  uint8_t wire[PAYMENT_PROFILE_WIRE_LEN], terms[32], allocation[32];
  uint8_t digest[32], decision[16];
  char instance_hex[33], handle_hex[33], request_hex[65], hash_hex[65];
  char digest_hex[65], decision_hex[33];
  char *command = NULL, *reply = NULL, *first = NULL;
  uint64_t revision;
  (void)arg;
  local_controller(&conn);
  payment_replies = smartlist_new();
  MOCK(control_write_reply, capture_payment_reply);
  MOCK(relay_send_command_from_edge_, capture_payment_wire);
  payment_wire_replies = 0;
  monotime_enable_test_mocking();
  monotime_set_mock_time_nsec(INT64_C(1000000000));
  monotime_coarse_set_mock_time_nsec(INT64_C(1000000000));
  timers_initialize();
  control_payment_init();
  policy.rate_msat = 1000;
  policy.initial_handshake_fee_msat = 10;
  policy.grace_ms = 15000;
  policy.max_age_ms = 1800000;
  policy.max_periods = 3;
  policy.setup_timeout_ms = 30000;
  memset(keys.binding, 2, 32);
  memset(keys.start_request, 5, 32);
  memset(keys.start_reply, 6, 32);
  memset(fee_hash, 0x99, 32);
  memset(decision, 0x77, 16);
  for (unsigned i = 0; i < 10; ++i)
    ids[i][0] = i+1;
  circ = or_circuit_new(0, NULL);
  circ->base_.purpose = CIRCUIT_PURPOSE_OR;
  circ->payment_export_requested = true;
  circ->payment_keys = tor_memdup(&keys, sizeof(keys));
  tt_int_op(payment_circuit_attach(circ, &policy, ids, fee_hash, 1000, 1000),
            OP_EQ, PAYMENT_CIRCUIT_OK);
  tt_int_op(control_payment_binding(TO_CIRCUIT(circ), instance, handle),
            OP_EQ, 0);
  payment_test_hex(instance_hex, instance, 16);
  payment_test_hex(handle_hex, handle, 16);
  payment_test_hex(hash_hex, fee_hash, 32);
  payment_test_hex(decision_hex, decision, 16);
  tt_int_op(payment_profile_terms_digest(terms, &policy), OP_EQ, 0);
  tt_int_op(payment_profile_initial_digest(allocation, keys.binding, terms, ids),
            OP_EQ, 0);
  commit.command = PAYMENT_PROFILE_COMMIT;
  commit.u.commit.policy = policy;
  memset(commit.u.commit.nonce, 0x11, 16);
  memcpy(commit.u.commit.allocation, allocation, 32);
  tt_int_op(payment_profile_encode(wire, sizeof(wire), &commit,
              keys.start_request, keys.binding), OP_EQ, 0);
  message.command = PAYMENT_PROFILE_COMMIT;
  message.body = wire;
  message.length = sizeof(wire);
  tt_int_op(payment_circuit_handle_relay(circ, &message, 1000), OP_EQ, 0);
  tt_int_op(payment_circuit_get_admission(circ, 0, 1000, &snapshot), OP_EQ,
            PAYMENT_CIRCUIT_OK);
  payment_test_hex(request_hex, snapshot.request_digest, 32);
  revision = payment_circuit_revision(circ);
  tor_asprintf(&command, "ELTOR_PAYMENT_ADMISSION_GET 1 %s %s 0\r\n",
               instance_hex, handle_hex);
  control_payment_handle_command(&conn, command, strlen(command));
  reply = collect_payment_replies();
  tt_assert(strstr(reply, "250-ELTOR_ADMISSION 1 "));
  tt_assert(strstr(reply, "250-BINDING "));
  tt_assert(strstr(reply, "250-STATE ADMISSION_PENDING "));
  tt_assert(strstr(reply, "250-CLOCK 0 -\r\n"));
  tt_u64_op(payment_circuit_revision(circ), OP_EQ, revision);
  tt_uint_op(payment_wire_replies, OP_EQ, 0);
  tor_free(command);
  tor_free(reply);
  tor_asprintf(&command,
      "ELTOR_PAYMENT_ADMISSION_DECIDE 1 %s %s 0 %s %s RESERVED\r\n",
      instance_hex, handle_hex, request_hex, decision_hex);
  control_payment_handle_command(&conn, command, strlen(command));
  first = collect_payment_replies();
  tt_assert(strstr(first, "250 ELTOR_ADMISSION_DECIDED 1 "));
  tt_uint_op(payment_wire_replies, OP_EQ, 1);
  revision = payment_circuit_revision(circ);
  control_payment_handle_command(&conn, command, strlen(command));
  reply = collect_payment_replies();
  tt_str_op(reply, OP_EQ, first);
  tt_uint_op(payment_wire_replies, OP_EQ, 1);
  tt_u64_op(payment_circuit_revision(circ), OP_EQ, revision);
  tor_free(command);
  tor_free(reply);
  tor_free(first);
  memset(decision, 0x44, 16);
  payment_test_hex(decision_hex, decision, 16);
  /* A well-framed assertion with a noncanonical ledger record is rejected
   * before authorization, even for the authenticated local authority. */
  tor_asprintf(&command,
      "ELTOR_PAYMENT_AUTHORIZE 1 %s %s %s 0 10 %s " ZERO32 "\r\n",
      instance_hex, handle_hex, decision_hex, hash_hex);
  control_payment_handle_command(&conn, command, strlen(command));
  reply = collect_payment_replies();
  tt_str_op(reply, OP_EQ, "512 BAD_ARGUMENT\r\n");
  tt_u64_op(payment_circuit_revision(circ), OP_EQ, revision);
  tor_free(command);
  tor_free(reply);
  tt_int_op(control_payment_record_digest(digest, instance, handle, decision,
      0, 10, fee_hash, terms, allocation), OP_EQ, 0);
  payment_test_hex(digest_hex, digest, 32);
  tor_asprintf(&command,
      "ELTOR_PAYMENT_AUTHORIZE 1 %s %s %s 0 10 %s %s\r\n",
      instance_hex, handle_hex, decision_hex, hash_hex, digest_hex);
  control_payment_handle_command(&conn, command, strlen(command));
  first = collect_payment_replies();
  tt_assert(strstr(first, "250 ELTOR_AUTHORIZED 1 "));
  tt_assert(!payment_circuit_paid_active(circ));
  revision = payment_circuit_revision(circ);
  control_payment_handle_command(&conn, command, strlen(command));
  reply = collect_payment_replies();
  tt_str_op(reply, OP_EQ, first);
  tt_u64_op(payment_circuit_revision(circ), OP_EQ, revision);
  tt_uint_op(payment_wire_replies, OP_EQ, 1);
  tor_free(reply);
  payment_circuit_close(circ);
  control_payment_handle_command(&conn, command, strlen(command));
  reply = collect_payment_replies();
  tt_str_op(reply, OP_EQ, "552 UNKNOWN_CIRCUIT\r\n");
 done:
  circuit_free_all();
  control_payment_free_all();
  timers_shutdown();
  monotime_disable_test_mocking();
  UNMOCK(control_write_reply);
  UNMOCK(relay_send_command_from_edge_);
  tor_free(command);
  tor_free(reply);
  tor_free(first);
  if (payment_replies) {
    SMARTLIST_FOREACH(payment_replies, char *, item, tor_free(item));
    smartlist_free(payment_replies);
  }
}

/* Operator-lowered arena ceilings must fail before allocating inventory rows,
 * preserve the existing immutable registry, and release every reservation. */
static void
test_control_payment_resource_bounds(void *arg)
{
  protocol_budget_limits_t limits;
  protocol_budget_memory_t blocker = {0};
  protocol_budget_t *budget = NULL;
  control_connection_t conn;
  origin_circuit_t circ;
  const char *command = "ELTOR_PAYMENT_LIST 1 - -\r\n";
  char *reply = NULL;
  uint32_t registry_bytes, baseline;
  (void)arg;
  local_controller(&conn);
  memset(&circ, 0, sizeof(circ));
  circ.base_.magic = ORIGIN_CIRCUIT_MAGIC;
  payment_replies = smartlist_new();
  MOCK(control_write_reply, capture_payment_reply);
  monotime_enable_test_mocking();
  monotime_set_mock_time_nsec(INT64_C(1000000000));
  protocol_budget_default_limits(&limits);
  limits.arena_bytes = 1024;
  limits.max_slot_bytes = 512;
  tt_int_op(payment_resources_configure(&limits), OP_EQ, 0);
  control_payment_init();
  budget = payment_resources_protocol();
  baseline = budget->arena_used;
  tt_uint_op(baseline, OP_GT, 0);
  tt_int_op(control_payment_register(&circ.base_, CONTROL_PAYMENT_ORIGIN,
                                     1, true), OP_EQ, -1);
  control_payment_handle_command(&conn, command, strlen(command));
  reply = collect_payment_replies();
  tt_str_op(reply, OP_EQ, "451 CAPACITY\r\n");
  tor_free(reply);
  control_payment_free_all();
  tt_int_op(payment_resources_free_all(), OP_EQ, 0);

  budget = payment_resources_protocol();
  baseline = budget->arena_used;
  control_payment_init();
  registry_bytes = budget->arena_used;
  tt_uint_op(registry_bytes, OP_GT, 1024);
  tt_int_op(control_payment_register(&circ.base_, CONTROL_PAYMENT_ORIGIN,
                                     1, true), OP_EQ, 0);
  /* Leave less than one inventory row free. A failed query reserves nothing. */
  tt_int_op(payment_resources_reserve(&blocker,
      budget->limits.arena_bytes - registry_bytes - 1), OP_EQ,
      PROTOCOL_BUDGET_OK);
  control_payment_handle_command(&conn, command, strlen(command));
  reply = collect_payment_replies();
  tt_str_op(reply, OP_EQ, "451 CAPACITY\r\n");
  tor_free(reply);
  tt_uint_op(budget->arena_used, OP_EQ, budget->limits.arena_bytes - 1);
  tt_int_op(payment_resources_release(&blocker), OP_EQ, PROTOCOL_BUDGET_OK);
  control_payment_handle_command(&conn, command, strlen(command));
  reply = collect_payment_replies();
  tt_assert(strstr(reply, "250-CIRCUIT "));
  tt_uint_op(budget->arena_used, OP_GT, registry_bytes);
  tor_free(reply);
  control_payment_connection_closed(&conn);
  tt_uint_op(budget->arena_used, OP_EQ, registry_bytes);
  /* Releasing a snapshot twice cannot release the registry lease. */
  control_payment_connection_closed(&conn);
  tt_uint_op(budget->arena_used, OP_EQ, registry_bytes);
  control_payment_free_all();
  tt_uint_op(budget->arena_used, OP_EQ, baseline);
  tt_int_op(payment_resources_free_all(), OP_EQ, 0);
 done:
  (void)payment_resources_release(&blocker);
  control_payment_free_all();
  (void)payment_resources_free_all();
  monotime_disable_test_mocking();
  UNMOCK(control_write_reply);
  tor_free(reply);
  if (payment_replies) {
    SMARTLIST_FOREACH(payment_replies, char *, item, tor_free(item));
    smartlist_free(payment_replies);
  }
}

static void
test_control_payment_output_backpressure(void *arg)
{
  control_connection_t conn, other;
  origin_circuit_t *circuits = NULL;
  protocol_budget_memory_t blocker = {0};
  protocol_budget_t *owner;
  uint32_t registry, with_output;
  size_t before;
  const char *command = "ELTOR_PAYMENT_LIST 1 - -\r\n";
  (void)arg;
  local_controller(&conn); local_controller(&other);
  conn.base_.outbuf = buf_new(); other.base_.outbuf = buf_new();
  MOCK(connection_write_to_buf_impl_, capture_payment_output);
  MOCK(connection_mark_for_close_internal_, capture_payment_disconnect);
  monotime_enable_test_mocking();
  monotime_set_mock_time_nsec(INT64_C(1000000000));
  control_payment_init();
  owner = payment_resources_protocol();
  registry = owner->arena_used;
  /* Leave room for exactly one bounded output owner plus a 128-row snapshot.
   * A nonreading controller cannot multiply this with another connection. */
  tt_int_op(payment_resources_reserve(&blocker,
      owner->limits.arena_bytes - registry -
      CONTROL_PAYMENT_OUTPUT_RESERVATION_BYTES -
      CONTROL_PAYMENT_RESPONSE_BYTES - 16384), OP_EQ, PROTOCOL_BUDGET_OK);
  circuits = tor_calloc(128, sizeof(*circuits));
  for (unsigned i = 0; i < 128; ++i) {
    circuits[i].base_.magic = ORIGIN_CIRCUIT_MAGIC;
    tt_int_op(control_payment_register(&circuits[i].base_,
        CONTROL_PAYMENT_ORIGIN, 1, true), OP_EQ, 0);
  }
  control_payment_handle_command(&conn, command, strlen(command));
  tt_uint_op(buf_datalen(conn.base_.outbuf), OP_GT, 0);
  tt_assert(conn.payment_output);
  with_output = owner->arena_used;
  control_payment_handle_command(&other, command, strlen(command));
  tt_assert(other.base_.marked_for_close);
  tt_uint_op(buf_datalen(other.base_.outbuf), OP_EQ, 0);
  tt_ptr_op(other.payment_output, OP_EQ, NULL);
  tt_uint_op(owner->arena_used, OP_EQ, with_output);
  /* Before formatting each response, reserve its entire bounded capacity.
   * At the backlog ceiling close without appending a partial response. */
  before = buf_datalen(conn.base_.outbuf);
  for (unsigned i = 1; i < 64 && !conn.base_.marked_for_close; ++i) {
    monotime_set_mock_time_nsec((int64_t)(i+1) * INT64_C(1000000000));
    before = buf_datalen(conn.base_.outbuf);
    control_payment_handle_command(&conn, command, strlen(command));
  }
  tt_assert(conn.base_.marked_for_close);
  tt_uint_op(buf_datalen(conn.base_.outbuf), OP_EQ, before);
  tt_uint_op(before, OP_LE, CONTROL_PAYMENT_OUTPUT_BYTES);
  tt_uint_op(buf_allocation(conn.base_.outbuf), OP_LE,
              CONTROL_PAYMENT_OUTPUT_RESERVATION_BYTES);
  /* Retain output accounting through partial drainage, then release only
   * after actual native chunks are gone. Repeated cleanup is idempotent. */
  uint32_t retained = owner->arena_used;
  buf_drain(conn.base_.outbuf, before / 2);
  control_payment_finished_flushing(&conn);
  tt_uint_op(owner->arena_used, OP_EQ, retained);
  buf_clear(conn.base_.outbuf);
  control_payment_finished_flushing(&conn);
  tt_ptr_op(conn.payment_output, OP_EQ, NULL);
  tt_uint_op(owner->arena_used, OP_LT, retained);
  control_payment_connection_closed(&conn);
  control_payment_connection_closed(&conn);
  tt_int_op(payment_resources_release(&blocker), OP_EQ, PROTOCOL_BUDGET_OK);
  tt_uint_op(owner->arena_used, OP_EQ, registry);
  /* Legacy control output is not subjected to the new payment render scope. */
  conn.base_.marked_for_close = 0;
  control_write_endreply(&conn, 250, "LEGACY");
  tt_uint_op(buf_datalen(conn.base_.outbuf), OP_GT, 0);
  tt_ptr_op(conn.payment_output, OP_EQ, NULL);
  tt_uint_op(owner->arena_used, OP_EQ, registry);
 done:
  control_payment_connection_closed(&conn);
  control_payment_connection_closed(&other);
  (void)payment_resources_release(&blocker);
  control_payment_free_all();
  (void)payment_resources_free_all();
  monotime_disable_test_mocking();
  UNMOCK(connection_write_to_buf_impl_);
  UNMOCK(connection_mark_for_close_internal_);
  buf_free(conn.base_.outbuf); buf_free(other.base_.outbuf);
  tor_free(circuits);
}

#define CONTROL_PAYMENT_TEST(name) \
  { #name, test_control_payment_##name, TT_FORK, NULL, NULL }
struct testcase_t control_payment_tests[] = {
  CONTROL_PAYMENT_TEST(parser),
  CONTROL_PAYMENT_TEST(record_digest),
  CONTROL_PAYMENT_TEST(authority),
  CONTROL_PAYMENT_TEST(inventory),
  CONTROL_PAYMENT_TEST(query_and_snapshot_bounds),
  CONTROL_PAYMENT_TEST(event_bound),
  CONTROL_PAYMENT_TEST(relay_bridge),
  CONTROL_PAYMENT_TEST(resource_bounds),
  CONTROL_PAYMENT_TEST(output_backpressure),
  END_OF_TESTCASES
};
