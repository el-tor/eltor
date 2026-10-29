/* Copyright (c) 2026, The El Tor Project. */
/* See LICENSE for licensing information. */
#include "orconfig.h"
#include "core/or/or.h"
#include "feature/control/control_payment.h"
#include "feature/control/control.h"
#include "feature/control/control_connection_st.h"
#include "feature/control/control_proto.h"
#include "feature/control/control_events.h"
#include "core/mainloop/connection.h"
#include "core/or/circuitlist.h"
#include "core/or/circuit_st.h"
#include "core/or/or_circuit_st.h"
#include "core/or/origin_circuit_st.h"
#include "lib/crypt_ops/crypto_rand.h"
#include "lib/crypt_ops/crypto_cipher.h"
#include "lib/crypt_ops/crypto_digest.h"
#include "lib/crypt_ops/crypto_util.h"
#include "lib/time/compat_time.h"
#include <string.h>

typedef struct command_name_t {
  const char *name;
  control_payment_command_t command;
  unsigned tokens;
} command_name_t;
static const command_name_t names[] = {
  { "ELTOR_CIRCUIT_BIND", CONTROL_PAYMENT_BIND, 3 },
  { "ELTOR_PAYMENT_LIST", CONTROL_PAYMENT_LIST, 4 },
  { "ELTOR_INITIAL_PREPARE", CONTROL_PAYMENT_INITIAL_PREPARE, 8 },
  { "ELTOR_INITIAL_START", CONTROL_PAYMENT_INITIAL_START, 7 },
  { "ELTOR_INITIAL_GET", CONTROL_PAYMENT_INITIAL_GET, 6 },
  { "ELTOR_INITIAL_REFRESH", CONTROL_PAYMENT_INITIAL_REFRESH, 7 },
  { "ELTOR_RENEW_PREPARE", CONTROL_PAYMENT_RENEW_PREPARE, 12 },
  { "ELTOR_PAYMENT_GET", CONTROL_PAYMENT_GET, 6 },
  { "ELTOR_PAYMENT_ADMISSION_GET", CONTROL_PAYMENT_ADMISSION_GET, 5 },
  { "ELTOR_PAYMENT_ADMISSION_DECIDE", CONTROL_PAYMENT_ADMISSION_DECIDE, 8 },
  { "ELTOR_PAYMENT_REGISTRATION_GET", CONTROL_PAYMENT_REGISTRATION_GET, 5 },
  { "ELTOR_PAYMENT_AUTHORIZE", CONTROL_PAYMENT_AUTHORIZE, 9 }
};

bool
control_payment_is_command(const char *name)
{
  if (!name)
    return false;
  for (unsigned i = 0; i < ARRAY_LENGTH(names); ++i)
    if (!strcasecmp(name, names[i].name))
      return true;
  return false;
}

static bool
parse_hex(uint8_t *out, size_t size, const char *s)
{
  if (strlen(s) != size * 2)
    return false;
  for (size_t i = 0; i < size * 2; ++i) {
    unsigned char c = s[i];
    unsigned n;
    if (c >= '0' && c <= '9')
      n = c - '0';
    else if (c >= 'a' && c <= 'f')
      n = c - 'a' + 10;
    else
      return false;
    if (!(i & 1))
      out[i / 2] = n << 4;
    else
      out[i / 2] |= n;
  }
  return true;
}

static void
lower_hex(char *out, const uint8_t *bytes, size_t n)
{
  static const char digits[] = "0123456789abcdef";
  for (size_t i = 0; i < n; ++i) {
    out[2*i] = digits[bytes[i] >> 4];
    out[2*i+1] = digits[bytes[i] & 15];
  }
  out[2*n] = 0;
}

static bool
parse_u64(uint64_t *out, const char *s, uint64_t max)
{
  uint64_t v = 0;
  if (!*s || (s[0] == '0' && s[1]))
    return false;
  for (; *s; ++s) {
    unsigned d;
    if (*s < '0' || *s > '9')
      return false;
    d = *s - '0';
    if (v > max / 10 || (v == max / 10 && d > max % 10))
      return false;
    v = v * 10 + d;
  }
  *out = v;
  return true;
}

static bool
nonzero(const uint8_t *p, size_t n)
{
  uint8_t v = 0;
  for (size_t i = 0; i < n; ++i)
    v |= p[i];
  return v != 0;
}

int
control_payment_parse(const char *line, size_t len,
                      control_payment_request_t *out)
{
  control_payment_request_t r = {0};
  char *copy = NULL, *token[16];
  unsigned count = 0;
  const command_name_t *definition = NULL;
  uint64_t value;
  int result = -1;
  if (!out)
    return -1;
  memset(out, 0, sizeof(*out));
  if (!line || len < 4 || len > CONTROL_PAYMENT_MAX_LINE ||
      line[len-2] != '\r' || line[len-1] != '\n')
    return -1;
  /* Validate original framing before tokenization; no normalization of tabs,
   * duplicate spaces, embedded NUL, quotes or trailing whitespace. */
  for (size_t i = 0; i < len-2; ++i) {
    unsigned char c = line[i];
    if (c < 0x20 || c > 0x7e || c == '"' || c == '\'')
      return -1;
    if (c == ' ' && (!i || i == len-3 || line[i-1] == ' '))
      return -1;
  }
  copy = tor_memdup_nulterm(line, len-2);
  token[count++] = copy;
  for (char *p = copy; *p; ++p) {
    if (*p == ' ') {
      if (count == ARRAY_LENGTH(token))
        goto done;
      *p = 0;
      token[count++] = p+1;
    }
  }
  for (unsigned i = 0; i < ARRAY_LENGTH(names); ++i)
    if (!strcmp(token[0], names[i].name))
      definition = &names[i];
  if (!definition || count != definition->tokens || strcmp(token[1], "1"))
    goto done;
  r.command = definition->command;
#define HEX(field, position) \
  STMT_BEGIN { if (!parse_hex(r.field, sizeof(r.field), token[position])) \
    goto done; } STMT_END
#define NUMBER(field, position) \
  STMT_BEGIN { if (!parse_u64(&r.field, token[position], UINT64_MAX)) \
    goto done; } STMT_END
  if (r.command == CONTROL_PAYMENT_BIND) {
    if (!parse_u64(&value, token[2], UINT32_MAX) || !value)
      goto done;
    r.circuit_id = (uint32_t)value;
  } else if (r.command == CONTROL_PAYMENT_LIST) {
    r.first_page = !strcmp(token[2], "-") && !strcmp(token[3], "-");
    if (!r.first_page) {
      HEX(instance, 2);
      HEX(cursor, 3);
    }
  } else {
    HEX(instance, 2);
    HEX(handle, 3);
    if (r.command == CONTROL_PAYMENT_ADMISSION_GET ||
        r.command == CONTROL_PAYMENT_REGISTRATION_GET ||
        r.command == CONTROL_PAYMENT_ADMISSION_DECIDE) {
      NUMBER(period, 4);
      if (r.period > (UINT64_MAX - 10) / 10)
        goto done;
      if (r.command == CONTROL_PAYMENT_ADMISSION_DECIDE) {
        HEX(request_digest, 5);
        HEX(decision, 6);
        if (!nonzero(r.decision, sizeof(r.decision)))
          goto done;
        if (!strcmp(token[7], "RESERVED"))
          r.admission = PAYMENT_CIRCUIT_RESERVED;
        else if (!strcmp(token[7], "CONFLICT"))
          r.admission = PAYMENT_CIRCUIT_ID_CONFLICT;
        else if (!strcmp(token[7], "CAPACITY"))
          r.admission = PAYMENT_CIRCUIT_NO_CAPACITY;
        else
          goto done;
      }
    } else if (r.command == CONTROL_PAYMENT_AUTHORIZE) {
      HEX(decision, 4);
      NUMBER(round, 5);
      NUMBER(amount_msat, 6);
      HEX(payment_hash, 7);
      HEX(record_digest, 8);
      if (!nonzero(r.decision, sizeof(r.decision)) ||
          (r.amount_msat == 0) != !nonzero(r.payment_hash, 32))
        goto done;
    } else {
      if (!parse_u64(&value, token[4], 16) || !value)
        goto done;
      r.hop = (uint16_t)value;
      if (r.command == CONTROL_PAYMENT_GET ||
          r.command == CONTROL_PAYMENT_INITIAL_GET) {
        r.no_operation = !strcmp(token[5], "-");
        if (!r.no_operation)
          HEX(operation, 5);
      } else {
        HEX(operation, 5);
        if (r.command == CONTROL_PAYMENT_RENEW_PREPARE) {
          NUMBER(period, 6);
          NUMBER(first_round, 7);
          HEX(nonce, 8);
          HEX(terms, 9);
          HEX(parent, 10);
          if (!parse_hex(&r.ids[0][0], sizeof(r.ids), token[11]) ||
              !r.period || r.period > (UINT64_MAX - 10) / 10 ||
              r.first_round != r.period * 10 + 1 ||
              !payment_profile_ids_valid(r.ids))
            goto done;
        } else {
          HEX(nonce, 6);
          if (r.command == CONTROL_PAYMENT_INITIAL_PREPARE) {
            payment_profile_policy_t policy;
            HEX(policy, 7);
            if (payment_profile_policy_decode(&policy, r.policy,
                                               sizeof(r.policy)) < 0)
              goto done;
          }
        }
      }
    }
  }
#undef HEX
#undef NUMBER
  *out = r;
  result = 0;
 done:
  if (copy) {
    memwipe(copy, 0, len-2);
    tor_free(copy);
  }
  return result;
}

int
control_payment_record_digest(uint8_t out[32], const uint8_t instance[16],
    const uint8_t handle[16], const uint8_t decision[16], uint64_t round,
    uint64_t amount, const uint8_t payment_hash[32], const uint8_t terms[32],
    const uint8_t initial[32])
{
  uint8_t record[161];
  size_t at = 0;
  record[at++] = 1;
  memcpy(record+at, instance, 16); at += 16;
  memcpy(record+at, handle, 16); at += 16;
  memcpy(record+at, decision, 16); at += 16;
  for (unsigned i = 0; i < 8; ++i)
    record[at++] = (uint8_t)(round >> (56 - 8*i));
  for (unsigned i = 0; i < 8; ++i)
    record[at++] = (uint8_t)(amount >> (56 - 8*i));
  memcpy(record+at, payment_hash, 32); at += 32;
  memcpy(record+at, terms, 32); at += 32;
  memcpy(record+at, initial, 32);
  return crypto_digest256((char *)out, (const char *)record, sizeof(record),
                           DIGEST_SHA256);
}

#define CONTROL_PAYMENT_RECORDS \
  (CONTROL_PAYMENT_MAX_LIVE + CONTROL_PAYMENT_MAX_TOMBSTONES)
#define CONTROL_PAYMENT_CURSOR_PAGES \
  (CONTROL_PAYMENT_MAX_LIVE / CONTROL_PAYMENT_PAGE_ROWS)

typedef struct payment_control_record_t {
  circuit_t *circ;
  uint8_t handle[16];
  control_payment_role_t role;
  uint64_t revision, closed_ms, closed_order;
  uint64_t last_query_ms[16];
  uint16_t query_seen, hops;
  bool used, closed, listed;
} payment_control_record_t;

typedef struct payment_inventory_row_t {
  uint8_t handle[16];
  control_payment_role_t role;
  uint64_t revision;
} payment_inventory_row_t;

typedef struct payment_inventory_t {
  control_connection_t *connection;
  payment_inventory_row_t *rows;
  uint8_t cursors[CONTROL_PAYMENT_CURSOR_PAGES][16];
  uint64_t created_ms, sequence;
  uint32_t count;
} payment_inventory_t;

static struct {
  uint8_t instance[16], handle_key[16];
  uint64_t handle_counter, sequence, close_counter, last_ms;
  uint64_t query_times[64];
  unsigned query_head, query_count, live, terminal;
  bool initialized, exhausted;
  payment_control_record_t records[CONTROL_PAYMENT_RECORDS];
  payment_inventory_t snapshots[CONTROL_PAYMENT_MAX_SNAPSHOTS];
} payment_control;

static void relay_transition(or_circuit_t *, payment_circuit_event_t);

bool
control_payment_authority(const control_connection_t *conn)
{
  if (!conn || conn->base_.state != CONTROL_CONN_STATE_OPEN ||
      conn->base_.marked_for_close)
    return false;
  if (conn->payment_local_fd)
    return true;
#ifdef AF_UNIX
  if (conn->base_.socket_family == AF_UNIX)
    return true;
#endif
  return tor_addr_is_loopback(&conn->base_.addr);
}

void
control_payment_init(void)
{
  if (payment_control.initialized)
    return;
  crypto_rand((char *)payment_control.instance, 16);
  crypto_rand((char *)payment_control.handle_key, 16);
  payment_control.last_ms = monotime_absolute_msec();
  payment_control.initialized = true;
  payment_circuit_set_event_callback(relay_transition);
}

/* AES-CTR's first keystream block is AES_K(counter). Distinct 128-bit inputs
 * form a permutation under the process-random key: unpredictable local handles
 * without keeping an unbounded history to avoid recycling after eviction. This
 * key is dedicated to local identifiers, never a traffic/payment/exporter key. */
static int
fresh_identifier(uint8_t out[16])
{
  uint8_t iv[16] = {0}, zero[16] = {0};
  uint64_t serial;
  crypto_cipher_t *cipher;
  int r;
  if (payment_control.exhausted ||
      payment_control.handle_counter == UINT64_MAX)
    return -1;
  serial = ++payment_control.handle_counter;
  for (unsigned i = 0; i < 8; ++i)
    iv[8+i] = serial >> (56 - i*8);
  cipher = crypto_cipher_new_with_iv((const char *)payment_control.handle_key,
                                     (const char *)iv);
  if (!cipher)
    return -1;
  r = crypto_cipher_encrypt(cipher, (char *)out, (const char *)zero, 16);
  crypto_cipher_free(cipher);
  return r;
}

static payment_control_record_t *
record_for_circuit(const circuit_t *circ)
{
  for (unsigned i = 0; i < CONTROL_PAYMENT_RECORDS; ++i) {
    payment_control_record_t *record = &payment_control.records[i];
    if (record->used && !record->closed && record->circ == circ)
      return record;
  }
  return NULL;
}

static payment_control_record_t *
record_for_handle(const uint8_t handle[16])
{
  for (unsigned i = 0; i < CONTROL_PAYMENT_RECORDS; ++i) {
    payment_control_record_t *record = &payment_control.records[i];
    if (record->used && !record->closed &&
        tor_memeq(record->handle, handle, 16))
      return record;
  }
  return NULL;
}

static void
prune_records(uint64_t now_ms)
{
  for (unsigned i = 0; i < CONTROL_PAYMENT_RECORDS; ++i) {
    payment_control_record_t *r = &payment_control.records[i];
    if (r->used && r->closed && now_ms >= r->closed_ms &&
        now_ms - r->closed_ms >= 60000) {
      memset(r, 0, sizeof(*r));
      --payment_control.terminal;
    }
  }
}

static const char *
role_name(control_payment_role_t role)
{
  return role == CONTROL_PAYMENT_RELAY ? "RELAY" : "ORIGIN";
}

static void
emit_record(payment_control_record_t *record, const char *kind)
{
  char instance[33], handle[33], line[256];
  if (!record->listed)
    return;
  if (payment_control.sequence == UINT64_MAX) {
    payment_control.exhausted = true;
    return;
  }
  lower_hex(instance, payment_control.instance, 16);
  lower_hex(handle, record->handle, 16);
  ++payment_control.sequence;
  tor_snprintf(line, sizeof(line),
      "650 ELTOR_PAYMENT_STATE 1 %s %"PRIu64" %s %s %"PRIu64" %s\r\n",
      instance, payment_control.sequence, handle, role_name(record->role),
      record->revision, kind);
  control_event_payment_state(line);
}

int
control_payment_register(circuit_t *circ, control_payment_role_t role,
                         uint16_t hops, bool listed)
{
  payment_control_record_t *record;
  uint64_t now_ms = monotime_absolute_msec();
  if (!circ || !hops || hops > 16 ||
      (role != CONTROL_PAYMENT_ORIGIN && role != CONTROL_PAYMENT_RELAY))
    return -1;
  control_payment_init();
  record = record_for_circuit(circ);
  if (record) {
    /* The construction owner may mark an origin as profiled after its
     * authenticated negotiation, but cannot replace identity or role. */
    if (record->role != role || record->hops != hops)
      return -1;
    if (listed && !record->listed) {
      record->listed = true;
      emit_record(record, "REGISTERED");
    }
    return 0;
  }
  if (payment_control.exhausted || now_ms < payment_control.last_ms ||
      payment_control.live >= CONTROL_PAYMENT_MAX_LIVE)
    return -1;
  payment_control.last_ms = now_ms;
  prune_records(now_ms);
  for (unsigned i = 0; i < CONTROL_PAYMENT_RECORDS; ++i) {
    record = &payment_control.records[i];
    if (record->used)
      continue;
    if (fresh_identifier(record->handle) < 0)
      return -1;
    record->used = true;
    record->circ = circ;
    record->role = role;
    record->hops = hops;
    record->listed = listed;
    record->revision = role == CONTROL_PAYMENT_RELAY ?
      payment_circuit_revision(TO_OR_CIRCUIT(circ)) : 1;
    if (!record->revision)
      record->revision = 1;
    ++payment_control.live;
    emit_record(record, "REGISTERED");
    return 0;
  }
  return -1;
}

int
control_payment_binding(const circuit_t *circ, uint8_t instance[16],
                        uint8_t handle[16])
{
  payment_control_record_t *record = record_for_circuit(circ);
  if (!record)
    return -1;
  memcpy(instance, payment_control.instance, 16);
  memcpy(handle, record->handle, 16);
  return 0;
}

static void
close_record(payment_control_record_t *record, uint64_t now_ms)
{
  record->closed = true;
  record->closed_ms = now_ms;
  record->circ = NULL;
  --payment_control.live;
  if (payment_control.close_counter == UINT64_MAX)
    payment_control.exhausted = true;
  else
    ++payment_control.close_counter;
  record->closed_order = payment_control.close_counter;
  ++payment_control.terminal;
  if (payment_control.terminal > CONTROL_PAYMENT_MAX_TOMBSTONES) {
    payment_control_record_t *oldest = NULL;
    for (unsigned i = 0; i < CONTROL_PAYMENT_RECORDS; ++i) {
      payment_control_record_t *r = &payment_control.records[i];
      if (r->used && r->closed &&
          (!oldest || r->closed_order < oldest->closed_order))
        oldest = r;
    }
    if (oldest) {
      memset(oldest, 0, sizeof(*oldest));
      --payment_control.terminal;
    }
  }
}

void
control_payment_circuit_closed(circuit_t *circ)
{
  payment_control_record_t *record = record_for_circuit(circ);
  if (!record)
    return;
  if (record->revision == UINT64_MAX)
    payment_control.exhausted = true;
  else
    ++record->revision;
  emit_record(record, "CLOSED");
  close_record(record, monotime_absolute_msec());
}

static void
relay_transition(or_circuit_t *circ, payment_circuit_event_t event)
{
  static const char *const kinds[] = {
    "REGISTERED", "ADMISSION_PENDING", "COMMITTED", "START_REQUESTED",
    "AUTHORIZED", "ROUND_ACTIVE", "RENEW_ADMITTED", "RENEW_REFUSED", "GRACE",
    "EXPIRED", "CLOSED"
  };
  payment_control_record_t *record;
  if ((unsigned)event >= ARRAY_LENGTH(kinds))
    return;
  record = record_for_circuit(TO_CIRCUIT(circ));
  if (!record) {
    if (event != PAYMENT_CIRCUIT_EVENT_REGISTERED ||
        control_payment_register(TO_CIRCUIT(circ), CONTROL_PAYMENT_RELAY,
                                 1, true) < 0)
      return;
    return; /* register emitted the one REGISTERED event. */
  }
  record->revision = payment_circuit_revision(circ);
  if (event == PAYMENT_CIRCUIT_EVENT_REGISTERED)
    record->listed = true;
  emit_record(record, kinds[event]);
  if (event == PAYMENT_CIRCUIT_EVENT_CLOSED)
    close_record(record, monotime_absolute_msec());
}

static void
snapshot_clear(payment_inventory_t *snapshot)
{
  tor_free(snapshot->rows);
  memset(snapshot, 0, sizeof(*snapshot));
}

void
control_payment_connection_closed(control_connection_t *conn)
{
  for (unsigned i = 0; i < CONTROL_PAYMENT_MAX_SNAPSHOTS; ++i)
    if (payment_control.snapshots[i].connection == conn)
      snapshot_clear(&payment_control.snapshots[i]);
}

void
control_payment_finished_flushing(control_connection_t *conn)
{
  conn->payment_events_queued = 0;
}

void
control_payment_queue_event(control_connection_t *conn, const char *line)
{
  if (!control_payment_authority(conn))
    return;
  /* Reset only after the output buffer is actually empty. This conservative
   * bound may disconnect a continuously busy subscriber earlier than necessary,
   * but never permits an unbounded event backlog behind other control output. */
  if (!connection_get_outbuf_len(TO_CONN(conn)))
    conn->payment_events_queued = 0;
  if (conn->payment_events_queued >= 1024) {
    connection_mark_for_close(TO_CONN(conn));
    return;
  }
  ++conn->payment_events_queued;
  connection_write_str_to_buf(line, conn);
}

void
control_payment_free_all(void)
{
  for (unsigned i = 0; i < CONTROL_PAYMENT_MAX_SNAPSHOTS; ++i)
    snapshot_clear(&payment_control.snapshots[i]);
  payment_circuit_set_event_callback(NULL);
  memwipe(&payment_control, 0, sizeof(payment_control));
}

static bool
query_budget(payment_control_record_t *record, unsigned hop, uint64_t now_ms)
{
  if (now_ms < payment_control.last_ms)
    return false;
  payment_control.last_ms = now_ms;
  while (payment_control.query_count &&
         now_ms - payment_control.query_times[payment_control.query_head] >=
         1000) {
    payment_control.query_head = (payment_control.query_head + 1) % 64;
    --payment_control.query_count;
  }
  if (payment_control.query_count == 64)
    return false;
  if (record) {
    if (!hop || hop > 16 || hop > record->hops)
      return false;
    --hop;
    if ((record->query_seen & (1u << hop)) &&
        now_ms - record->last_query_ms[hop] < 1000)
      return false;
    record->query_seen |= 1u << hop;
    record->last_query_ms[hop] = now_ms;
  }
  payment_control.query_times[(payment_control.query_head +
                              payment_control.query_count) % 64] = now_ms;
  ++payment_control.query_count;
  return true;
}

static int
row_compare(const void *a, const void *b)
{
  const payment_inventory_row_t *left = a, *right = b;
  return memcmp(left->handle, right->handle, 16);
}

static void
reply_error(control_connection_t *conn, int code, const char *token)
{
  control_write_endreply(conn, code, token);
}

static void
reply_result_error(control_connection_t *conn, payment_circuit_result_t r)
{
  switch (r) {
    case PAYMENT_CIRCUIT_OBSERVATION_PENDING:
      reply_error(conn, 551, "STATE_TRANSITION_PENDING"); break;
    case PAYMENT_CIRCUIT_UNKNOWN_PERIOD:
      reply_error(conn, 552, "UNKNOWN_PERIOD"); break;
    case PAYMENT_CIRCUIT_UNCONFIRMED:
      reply_error(conn, 551, "INITIAL_STATE_UNCONFIRMED"); break;
    case PAYMENT_CIRCUIT_CONFLICT:
      reply_error(conn, 553, "OPERATION_CONFLICT"); break;
    case PAYMENT_CIRCUIT_EXPIRED:
      reply_error(conn, 551, "DEADLINE_EXPIRED"); break;
    case PAYMENT_CIRCUIT_CAPACITY:
      reply_error(conn, 451, "CAPACITY"); break;
    case PAYMENT_CIRCUIT_CLOSED:
      reply_error(conn, 552, "UNKNOWN_CIRCUIT"); break;
    case PAYMENT_CIRCUIT_INVALID:
    default:
      reply_error(conn, 512, "BAD_ARGUMENT"); break;
  }
}

static void
inventory_reply(control_connection_t *conn,
                const control_payment_request_t *request, uint64_t now_ms)
{
  payment_inventory_t *snapshot = NULL, *unused = NULL;
  unsigned page = 0;
  char instance[33], cursor[33];
  for (unsigned i = 0; i < CONTROL_PAYMENT_MAX_SNAPSHOTS; ++i) {
    payment_inventory_t *candidate = &payment_control.snapshots[i];
    if (candidate->connection && now_ms - candidate->created_ms >= 10000)
      snapshot_clear(candidate);
    if (candidate->connection == conn)
      snapshot = candidate;
    else if (!candidate->connection)
      unused = candidate;
  }
  if (!request->first_page) {
    bool found = false;
    if (!snapshot) {
      reply_error(conn, 552, "UNKNOWN_CURSOR");
      return;
    }
    for (unsigned i = 1; i < CONTROL_PAYMENT_CURSOR_PAGES; ++i) {
      if (i * CONTROL_PAYMENT_PAGE_ROWS >= snapshot->count)
        break;
      if (tor_memeq(request->cursor, snapshot->cursors[i], 16)) {
        page = i;
        found = true;
        break;
      }
    }
    if (!found) {
      reply_error(conn, 552, "UNKNOWN_CURSOR");
      return;
    }
  } else if (!snapshot) {
    unsigned count = 0;
    if (!unused) {
      reply_error(conn, 451, "CAPACITY");
      return;
    }
    snapshot = unused;
    for (unsigned i = 0; i < CONTROL_PAYMENT_RECORDS; ++i)
      if (payment_control.records[i].used &&
          !payment_control.records[i].closed &&
          payment_control.records[i].listed)
        ++count;
    if (count > CONTROL_PAYMENT_MAX_LIVE) {
      reply_error(conn, 451, "CAPACITY");
      return;
    }
    snapshot->rows = count ? tor_calloc(count, sizeof(*snapshot->rows)) : NULL;
    snapshot->count = count;
    snapshot->created_ms = now_ms;
    snapshot->sequence = payment_control.sequence;
    snapshot->connection = conn;
    count = 0;
    for (unsigned i = 0; i < CONTROL_PAYMENT_RECORDS; ++i) {
      const payment_control_record_t *r = &payment_control.records[i];
      payment_inventory_row_t *row;
      if (!r->used || r->closed || !r->listed)
        continue;
      row = &snapshot->rows[count++];
      memcpy(row->handle, r->handle, 16);
      row->role = r->role;
      row->revision = r->revision;
    }
    if (count > 1)
      qsort(snapshot->rows, count, sizeof(*snapshot->rows), row_compare);
    for (unsigned i = 1; i < CONTROL_PAYMENT_CURSOR_PAGES; ++i) {
      if (i * CONTROL_PAYMENT_PAGE_ROWS >= snapshot->count)
        break;
      if (fresh_identifier(snapshot->cursors[i]) < 0) {
        snapshot_clear(snapshot);
        reply_error(conn, 451, "CAPACITY");
        return;
      }
    }
  }
  lower_hex(instance, payment_control.instance, 16);
  if ((page+1) * CONTROL_PAYMENT_PAGE_ROWS < snapshot->count)
    lower_hex(cursor, snapshot->cursors[page+1], 16);
  else
    strlcpy(cursor, "-", sizeof(cursor));
  control_printf_midreply(conn, 250,
      "ELTOR_PAYMENT_LIST 1 %s %"PRIu64" %s", instance, snapshot->sequence,
      cursor);
  for (unsigned i = page * CONTROL_PAYMENT_PAGE_ROWS;
       i < snapshot->count && i < (page+1) * CONTROL_PAYMENT_PAGE_ROWS; ++i) {
    char handle[33];
    lower_hex(handle, snapshot->rows[i].handle, 16);
    control_printf_midreply(conn, 250, "CIRCUIT %s %s %"PRIu64, handle,
        role_name(snapshot->rows[i].role), snapshot->rows[i].revision);
  }
  send_control_done(conn);
}

static const char *
phase_name(payment_schedule_phase_t phase)
{
  switch (phase) {
    case PAYMENT_SCHEDULE_UNCOMMITTED: return "UNCOMMITTED";
    case PAYMENT_SCHEDULE_COMMITTED: return "COMMITTED";
    case PAYMENT_SCHEDULE_WAIT_PAYMENT: return "WAIT_PAYMENT";
    case PAYMENT_SCHEDULE_ACTIVE: return "ACTIVE";
    case PAYMENT_SCHEDULE_GRACE: return "GRACE";
    case PAYMENT_SCHEDULE_CLOSED: return "CLOSED";
    case PAYMENT_SCHEDULE_EXPIRED: return "EXPIRED";
  }
  return "UNCOMMITTED";
}

static const char *
authorization_name(payment_circuit_authorization_t authorization)
{
  switch (authorization) {
    case PAYMENT_CIRCUIT_AUTH_NONE: return "NONE";
    case PAYMENT_CIRCUIT_AUTHORIZED: return "AUTHORIZED";
    case PAYMENT_CIRCUIT_CONSUMED: return "CONSUMED";
  }
  return "NONE";
}

static void
snapshot_reply(control_connection_t *conn,
               const control_payment_request_t *request,
               const payment_control_record_t *record,
               const payment_circuit_snapshot_t *snapshot)
{
  char instance[33], handle[33], terms[111], initial[65], allocation[65];
  char binding[65], digest[65], hash[65], decision[33];
  uint8_t policy[PAYMENT_PROFILE_TERMS_LEN];
  if (payment_profile_policy_encode(policy, sizeof(policy),
                                     &snapshot->policy) < 0) {
    reply_error(conn, 551, "INITIAL_STATE_UNCONFIRMED");
    return;
  }
  lower_hex(instance, payment_control.instance, 16);
  lower_hex(handle, record->handle, 16);
  lower_hex(terms, policy, sizeof(policy));
  lower_hex(initial, snapshot->initial_allocation, 32);
  lower_hex(allocation, snapshot->allocation, 32);
  lower_hex(binding, snapshot->circuit_binding, 32);
  if (request->command == CONTROL_PAYMENT_ADMISSION_GET) {
    lower_hex(digest, snapshot->request_digest, 32);
    control_printf_midreply(conn, 250,
        "ELTOR_ADMISSION 1 %s %s %"PRIu64" %"PRIu64" %s %"PRIu64,
        instance, handle, snapshot->revision, snapshot->period, digest,
        snapshot->admission_remaining_ms);
  }
  control_printf_midreply(conn, 250,
      "ELTOR_REGISTRATION 1 %s %s %"PRIu64" %"PRIu64,
      instance, handle, snapshot->revision, snapshot->period);
  control_printf_midreply(conn, 250, "POLICY %s %s %s %"PRIu64,
      terms, initial, allocation, snapshot->first_round);
  control_printf_midreply(conn, 250, "BINDING %s", binding);
  control_printf_midreply(conn, 250,
      "STATE %s %"PRIu64" %"PRIu64" %"PRIu64" %"PRIu64,
      snapshot->pending ? "ADMISSION_PENDING" : phase_name(snapshot->phase),
      snapshot->current_round, snapshot->elapsed_ms, snapshot->setup_remaining_ms,
      snapshot->enforcement_remaining_ms);
  lower_hex(hash, snapshot->fee.payment_hash, 32);
  if (snapshot->fee.authorization == PAYMENT_CIRCUIT_AUTH_NONE)
    strlcpy(decision, "-", sizeof(decision));
  else
    lower_hex(decision, snapshot->fee.decision, 16);
  control_printf_midreply(conn, 250, "FEE %"PRIu64" %s %s %s",
      snapshot->fee.amount_msat, hash, decision,
      authorization_name(snapshot->fee.authorization));
  for (unsigned i = 0; i < 10; ++i) {
    const payment_circuit_round_t *round = &snapshot->rounds[i];
    char id[65], windows[48];
    lower_hex(id, round->payment_id, 32);
    if (round->window_available && !snapshot->pending)
      tor_snprintf(windows, sizeof(windows), "%"PRIu64" %"PRIu64,
                   round->opens_in_ms, round->closes_in_ms);
    else
      strlcpy(windows, "- -", sizeof(windows));
    if (round->charge.authorization == PAYMENT_CIRCUIT_AUTH_NONE) {
      strlcpy(decision, "-", sizeof(decision));
      strlcpy(hash, "-", sizeof(hash));
    } else {
      lower_hex(decision, round->charge.decision, 16);
      lower_hex(hash, round->charge.payment_hash, 32);
    }
    control_printf_midreply(conn, 250,
        "ROUND %"PRIu64" %s %"PRIu64" %s %s %s %s",
        round->round, id, round->charge.amount_msat, windows, decision, hash,
        authorization_name(round->charge.authorization));
  }
  send_control_done(conn);
}

int
control_payment_handle_command(control_connection_t *conn,
                               const char *line, size_t len)
{
  control_payment_request_t request;
  payment_control_record_t *record = NULL;
  payment_circuit_snapshot_t snapshot;
  payment_circuit_result_t result;
  uint64_t now_ms = monotime_absolute_msec();
  bool query;
  char instance[33], handle[33], decision[33];
  if (!control_payment_authority(conn)) {
    reply_error(conn, 514, "AUTHENTICATION_REQUIRED");
    return 0;
  }
  if (control_payment_parse(line, len, &request) < 0) {
    reply_error(conn, 512, "BAD_ARGUMENT");
    return 0;
  }
  control_payment_init();
  if (payment_control.exhausted || now_ms < payment_control.last_ms) {
    reply_error(conn, 451, "CAPACITY");
    return 0;
  }
  if (request.command != CONTROL_PAYMENT_BIND &&
      !(request.command == CONTROL_PAYMENT_LIST && request.first_page) &&
      tor_memneq(request.instance, payment_control.instance, 16)) {
    reply_error(conn, 552, "STALE_INSTANCE");
    return 0;
  }
  if (request.command == CONTROL_PAYMENT_BIND) {
    origin_circuit_t *circ = circuit_get_by_global_id(request.circuit_id);
    if (circ && !circ->base_.marked_for_close)
      record = record_for_circuit(TO_CIRCUIT(circ));
  } else if (request.command != CONTROL_PAYMENT_LIST) {
    record = record_for_handle(request.handle);
    if (record && record->circ->marked_for_close)
      record = NULL;
  }
  query = request.command == CONTROL_PAYMENT_BIND ||
    request.command == CONTROL_PAYMENT_LIST ||
    request.command == CONTROL_PAYMENT_INITIAL_GET ||
    request.command == CONTROL_PAYMENT_GET ||
    request.command == CONTROL_PAYMENT_ADMISSION_GET ||
    request.command == CONTROL_PAYMENT_REGISTRATION_GET;
  if (record && request.hop && request.hop > record->hops) {
    reply_error(conn, 512, "BAD_ARGUMENT");
    return 0;
  }
  if (query && !query_budget(
      request.command == CONTROL_PAYMENT_BIND ? NULL : record,
      request.hop ? request.hop : 1, now_ms)) {
    reply_error(conn, 451, "CAPACITY");
    return 0;
  }
  if (request.command == CONTROL_PAYMENT_LIST) {
    inventory_reply(conn, &request, now_ms);
    return 0;
  }
  if (!record) {
    reply_error(conn, 552, "UNKNOWN_CIRCUIT");
    return 0;
  }
  lower_hex(instance, payment_control.instance, 16);
  lower_hex(handle, record->handle, 16);
  if (request.command == CONTROL_PAYMENT_BIND) {
    control_printf_endreply(conn, 250,
        "ELTOR_CIRCUIT 1 %s %s %u %"PRIu64, instance, handle,
        (unsigned)record->hops, record->revision);
    return 0;
  }
  if (request.command == CONTROL_PAYMENT_ADMISSION_GET ||
      request.command == CONTROL_PAYMENT_REGISTRATION_GET) {
    if (record->role != CONTROL_PAYMENT_RELAY) {
      reply_error(conn, 552, "UNKNOWN_CIRCUIT");
      return 0;
    }
    if (request.command == CONTROL_PAYMENT_ADMISSION_GET)
      result = payment_circuit_get_admission(TO_OR_CIRCUIT(record->circ),
          request.period, now_ms, &snapshot);
    else
      result = payment_circuit_get_registration(TO_OR_CIRCUIT(record->circ),
          request.period, now_ms, &snapshot);
    if (result != PAYMENT_CIRCUIT_OK)
      reply_result_error(conn, result);
    else
      snapshot_reply(conn, &request, record, &snapshot);
    return 0;
  }
  if (request.command == CONTROL_PAYMENT_ADMISSION_DECIDE) {
    if (record->role != CONTROL_PAYMENT_RELAY) {
      reply_error(conn, 552, "UNKNOWN_CIRCUIT");
      return 0;
    }
    result = payment_circuit_decide(TO_OR_CIRCUIT(record->circ), request.period,
        request.request_digest, request.decision, request.admission, now_ms);
    if (result != PAYMENT_CIRCUIT_OK) {
      reply_result_error(conn, result);
      return 0;
    }
    lower_hex(decision, request.decision, 16);
    control_printf_endreply(conn, 250,
        "ELTOR_ADMISSION_DECIDED 1 %s %s %"PRIu64" %s %"PRIu64,
        instance, handle, request.period, decision, record->revision);
    return 0;
  }
  if (request.command == CONTROL_PAYMENT_AUTHORIZE) {
    payment_circuit_charge_t authorization = {0};
    uint8_t digest[32];
    uint64_t period = request.round ? (request.round-1) / 10 : 0;
    if (record->role != CONTROL_PAYMENT_RELAY) {
      reply_error(conn, 552, "UNKNOWN_CIRCUIT");
      return 0;
    }
    result = payment_circuit_get_registration(TO_OR_CIRCUIT(record->circ),
                                              period, now_ms, &snapshot);
    if (result != PAYMENT_CIRCUIT_OK) {
      reply_result_error(conn, result);
      return 0;
    }
    if (control_payment_record_digest(digest, payment_control.instance,
          record->handle, request.decision, request.round, request.amount_msat,
          request.payment_hash, snapshot.terms,
          snapshot.initial_allocation) < 0 ||
        tor_memneq(digest, request.record_digest, 32)) {
      reply_error(conn, 512, "BAD_ARGUMENT");
      return 0;
    }
    memcpy(authorization.decision, request.decision, 16);
    memcpy(authorization.payment_hash, request.payment_hash, 32);
    memcpy(authorization.record_digest, request.record_digest, 32);
    authorization.amount_msat = request.amount_msat;
    authorization.authorization = PAYMENT_CIRCUIT_AUTHORIZED;
    result = payment_circuit_authorize(TO_OR_CIRCUIT(record->circ),
                                      request.round, &authorization, now_ms);
    if (result != PAYMENT_CIRCUIT_OK) {
      reply_result_error(conn, result);
      return 0;
    }
    lower_hex(decision, request.decision, 16);
    control_printf_endreply(conn, 250,
        "ELTOR_AUTHORIZED 1 %s %s %s %"PRIu64, instance, handle, decision,
        record->revision);
    return 0;
  }
  /* Origin operation/retry ownership has a separate live backend. Never
   * manufacture a QUEUED/VERIFIED response from syntax or controller claims. */
  if (record->role != CONTROL_PAYMENT_ORIGIN)
    reply_error(conn, 552, "UNKNOWN_CIRCUIT");
  else
    reply_error(conn, 551, "INITIAL_STATE_UNCONFIRMED");
  return 0;
}
