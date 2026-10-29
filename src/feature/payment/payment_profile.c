/* See LICENSE for licensing information. */
#include "orconfig.h"
#include "feature/payment/payment_profile.h"
#include "lib/crypt_ops/crypto_digest.h"
#include "lib/crypt_ops/crypto_hkdf.h"
#include "lib/crypt_ops/crypto_util.h"
#include "lib/ctime/di_ops.h"
#include <string.h>

/* Explicit byte operations keep unaligned data and host byte order out of the
 * format, including on architectures where unaligned integer loads trap. */
static uint64_t
read_be(const uint8_t *p, size_t n)
{
  uint64_t v = 0;
  for (size_t i = 0; i < n; ++i)
    v = (v << 8) | p[i];
  return v;
}

static void
write_be(uint8_t *p, uint64_t v, size_t n)
{
  for (size_t i = n; i > 0; --i) {
    p[i-1] = (uint8_t)v;
    v >>= 8;
  }
}

static int
all_zero(const uint8_t *p, size_t n)
{
  uint8_t v = 0;
  for (size_t i = 0; i < n; ++i)
    v |= p[i];
  return v == 0;
}

static int
policy_valid(const payment_profile_policy_t *p)
{
  return p && p->grace_ms <= PAYMENT_PROFILE_ROUND_MS &&
    p->max_age_ms > 0 && p->max_periods >= 2 && p->setup_timeout_ms > 0;
}

int
payment_profile_policy_encode(uint8_t *out, size_t len,
                              const payment_profile_policy_t *p)
{
  if (!out || len != PAYMENT_PROFILE_TERMS_LEN)
    return PAYMENT_PROFILE_ERR_LENGTH;
  memset(out, 0, len);
  if (!policy_valid(p))
    return PAYMENT_PROFILE_ERR_POLICY;
  out[0] = 1; out[1] = 1; out[2] = 10;
  write_be(out+3, p->rate_msat, 8);
  write_be(out+11, PAYMENT_PROFILE_ROUND_MS, 4);
  write_be(out+15, PAYMENT_PROFILE_ROUND_MS, 4);
  write_be(out+19, p->grace_ms, 4);
  write_be(out+23, p->paid_quota_bytes, 8);
  write_be(out+31, p->max_age_ms, 8);
  write_be(out+39, p->max_periods, 4);
  write_be(out+43, p->initial_handshake_fee_msat, 8);
  write_be(out+51, p->setup_timeout_ms, 4);
  return PAYMENT_PROFILE_OK;
}

int
payment_profile_policy_decode(payment_profile_policy_t *out,
                              const uint8_t *wire, size_t len)
{
  if (!out)
    return PAYMENT_PROFILE_ERR_BODY;
  memset(out, 0, sizeof(*out));
  if (!wire || len != PAYMENT_PROFILE_TERMS_LEN)
    return PAYMENT_PROFILE_ERR_LENGTH;
  if (wire[0] != 1 || wire[1] != 1 || wire[2] != 10 ||
      read_be(wire+11, 4) != PAYMENT_PROFILE_ROUND_MS ||
      read_be(wire+15, 4) != PAYMENT_PROFILE_ROUND_MS)
    return PAYMENT_PROFILE_ERR_POLICY;
  payment_profile_policy_t p = {0};
  p.rate_msat = read_be(wire+3, 8);
  p.grace_ms = (uint32_t)read_be(wire+19, 4);
  p.paid_quota_bytes = read_be(wire+23, 8);
  p.max_age_ms = read_be(wire+31, 8);
  p.max_periods = (uint32_t)read_be(wire+39, 4);
  p.initial_handshake_fee_msat = read_be(wire+43, 8);
  p.setup_timeout_ms = (uint32_t)read_be(wire+51, 4);
  if (!policy_valid(&p))
    return PAYMENT_PROFILE_ERR_POLICY;
  *out = p;
  return PAYMENT_PROFILE_OK;
}

int
payment_profile_ids_valid(const uint8_t ids[10][32])
{
  if (!ids)
    return 0;
  for (size_t i = 0; i < 10; ++i) {
    if (all_zero(ids[i], 32))
      return 0;
    for (size_t j = 0; j < i; ++j)
      if (tor_memeq(ids[i], ids[j], 32))
        return 0;
  }
  return 1;
}

/* D(s) is u16(strlen(s)) || s, without a terminating NUL. Domains below are
 * internal constants; caller-controlled lengths never reach this helper. */
static crypto_digest_t *
domain_digest(const char *domain)
{
  crypto_digest_t *d = crypto_digest256_new(DIGEST_SHA256);
  uint8_t len[2];
  write_be(len, strlen(domain), 2);
  crypto_digest_add_bytes(d, (const char *)len, 2);
  crypto_digest_add_bytes(d, domain, strlen(domain));
  return d;
}

static void
finish_digest(crypto_digest_t *d, uint8_t out[32])
{
  crypto_digest_get_digest(d, (char *)out, 32);
  crypto_digest_free(d);
}

void
payment_profile_keys_clear(payment_profile_keys_t *keys)
{
  if (keys)
    memwipe(keys, 0, sizeof(*keys));
}

void
payment_profile_export_clear(payment_profile_export_t *result)
{
  if (result)
    memwipe(result, 0, sizeof(*result));
}

void
payment_profile_keys_free_(payment_profile_keys_t *keys)
{
  if (!keys)
    return;
  payment_profile_keys_clear(keys);
  tor_free(keys);
}

int
payment_profile_export_take(payment_profile_keys_t **destination,
                            payment_profile_export_t *result, bool requested)
{
  if (!result)
    return -1;
  int ret = -1;
  if (destination && !*destination && result->valid == requested) {
    if (requested)
      *destination = tor_memdup(&result->keys, sizeof(result->keys));
    ret = 0;
  }
  payment_profile_export_clear(result);
  return ret;
}

int
payment_profile_derive_keys(payment_profile_keys_t *out,
                           const uint8_t seed[32],
                           const uint8_t *client, size_t client_len,
                           const uint8_t *server, size_t server_len)
{
  static const char *domains[] = {
    "eltor/payment-renew/v1/circuit-binding",
    "eltor/payment-renew/v1/request-key",
    "eltor/payment-renew/v1/reply-key",
    "eltor/payment-start/v1/request-key",
    "eltor/payment-start/v1/reply-key"
  };
  if (!out)
    return PAYMENT_PROFILE_ERR_BODY;
  payment_profile_keys_clear(out);
  if (!seed || (!client && client_len) || (!server && server_len))
    return PAYMENT_PROFILE_ERR_BODY;
  payment_profile_keys_t keys = {0};
  uint8_t salt[32], len[8], info[128];
  crypto_digest_t *d = crypto_digest256_new(DIGEST_SHA256);
  write_be(len, client_len, 8);
  crypto_digest_add_bytes(d, (const char *)len, 8);
  if (client_len)
    crypto_digest_add_bytes(d, (const char *)client, client_len);
  write_be(len, server_len, 8);
  crypto_digest_add_bytes(d, (const char *)len, 8);
  if (server_len)
    crypto_digest_add_bytes(d, (const char *)server, server_len);
  finish_digest(d, keys.context);
  d = domain_digest("eltor/payment-renew/v1/extract");
  finish_digest(d, salt);
  uint8_t *dest[] = { keys.binding, keys.renew_request, keys.renew_reply,
                      keys.start_request, keys.start_reply };
  int result = PAYMENT_PROFILE_OK;
  for (size_t i = 0; i < 5; ++i) {
    size_t n = strlen(domains[i]);
    write_be(info, n, 2);
    memcpy(info+2, domains[i], n);
    memcpy(info+2+n, keys.context, 32);
    if (crypto_expand_key_material_rfc5869_sha256(seed, 32, salt, 32,
                                                 info, 2+n+32,
                                                 dest[i], 32) < 0) {
      result = PAYMENT_PROFILE_ERR_BODY;
      break;
    }
  }
  if (result == PAYMENT_PROFILE_OK)
    *out = keys;
  payment_profile_keys_clear(&keys);
  memwipe(salt, 0, sizeof(salt));
  memwipe(info, 0, sizeof(info));
  return result;
}

int
payment_profile_terms_digest(uint8_t out[32],
                            const payment_profile_policy_t *policy)
{
  uint8_t terms[PAYMENT_PROFILE_TERMS_LEN];
  if (!out)
    return PAYMENT_PROFILE_ERR_BODY;
  memset(out, 0, 32);
  int r = payment_profile_policy_encode(terms, sizeof(terms), policy);
  if (r != PAYMENT_PROFILE_OK)
    return r;
  crypto_digest_t *d = domain_digest("eltor/payment-renew/v1/terms");
  crypto_digest_add_bytes(d, (const char *)terms, sizeof(terms));
  finish_digest(d, out);
  return PAYMENT_PROFILE_OK;
}

int
payment_profile_initial_digest(uint8_t out[32], const uint8_t binding[32],
                              const uint8_t terms[32],
                              const uint8_t ids[10][32])
{
  if (!out)
    return PAYMENT_PROFILE_ERR_BODY;
  memset(out, 0, 32);
  if (!binding || !terms || !payment_profile_ids_valid(ids))
    return PAYMENT_PROFILE_ERR_SEQUENCE;
  crypto_digest_t *d = domain_digest("eltor/payment-renew/v1/initial");
  crypto_digest_add_bytes(d, (const char *)binding, 32);
  crypto_digest_add_bytes(d, (const char *)terms, 32);
  crypto_digest_add_bytes(d, (const char *)ids, PAYMENT_PROFILE_IDS_LEN);
  finish_digest(d, out);
  return PAYMENT_PROFILE_OK;
}

int
payment_profile_request_digest(uint8_t out[32],
                              payment_profile_command_t command,
                              const uint8_t *wire, size_t len)
{
  if (!out)
    return PAYMENT_PROFILE_ERR_BODY;
  memset(out, 0, 32);
  if (!wire || len != PAYMENT_PROFILE_WIRE_LEN)
    return PAYMENT_PROFILE_ERR_LENGTH;
  const char *domain;
  if (command == PAYMENT_PROFILE_RENEW)
    domain = "eltor/payment-renew/v1/request-hash";
  else if (command == PAYMENT_PROFILE_COMMIT ||
           command == PAYMENT_PROFILE_START_STATUS)
    domain = "eltor/payment-start/v1/request";
  else
    return PAYMENT_PROFILE_ERR_HEADER;
  crypto_digest_t *d = domain_digest(domain);
  crypto_digest_add_bytes(d, (const char *)wire, len);
  finish_digest(d, out);
  return PAYMENT_PROFILE_OK;
}

int
payment_profile_allocation_digest(uint8_t out[32], const uint8_t binding[32],
                                 const uint8_t *wire, size_t len)
{
  if (!out)
    return PAYMENT_PROFILE_ERR_BODY;
  memset(out, 0, 32);
  if (!wire || len != PAYMENT_PROFILE_WIRE_LEN)
    return PAYMENT_PROFILE_ERR_LENGTH;
  if (!binding)
    return PAYMENT_PROFILE_ERR_BODY;
  crypto_digest_t *d = domain_digest("eltor/payment-renew/v1/allocation");
  crypto_digest_add_bytes(d, (const char *)binding, 32);
  crypto_digest_add_bytes(d, (const char *)wire, PAYMENT_PROFILE_BODY_LEN);
  finish_digest(d, out);
  return PAYMENT_PROFILE_OK;
}

static int
message_mac(uint8_t out[32], payment_profile_command_t command,
            const uint8_t *wire, const uint8_t key[32],
            const uint8_t binding[32])
{
  const char *domain;
  if (command == PAYMENT_PROFILE_RENEW)
    domain = "eltor/payment-renew/v1/request-mac";
  else if (command == PAYMENT_PROFILE_RENEWED)
    domain = "eltor/payment-renew/v1/reply-mac";
  else if (command >= PAYMENT_PROFILE_COMMIT &&
           command <= PAYMENT_PROFILE_STARTED_STATUS)
    domain = "eltor/payment-start/v1/mac";
  else
    return PAYMENT_PROFILE_ERR_HEADER;
  uint8_t input[600];
  size_t n = strlen(domain), off = 2+n;
  write_be(input, n, 2);
  memcpy(input+2, domain, n);
  memcpy(input+off, binding, 32); off += 32;
  input[off++] = (uint8_t)command;
  memcpy(input+off, wire, PAYMENT_PROFILE_BODY_LEN);
  off += PAYMENT_PROFILE_BODY_LEN;
  crypto_hmac_sha256((char *)out, (const char *)key, 32,
                     (const char *)input, off);
  memwipe(input, 0, sizeof(input));
  return PAYMENT_PROFILE_OK;
}

/* Check multiplication before evaluating it. Returned values never wrap. */
static int
renew_schedule(uint64_t period, uint64_t *first, uint64_t *activation)
{
  if (!period || period > (UINT64_MAX-1)/10 ||
      period > UINT64_MAX/(10*UINT64_C(60000)))
    return PAYMENT_PROFILE_ERR_SEQUENCE;
  *first = period*10+1;
  *activation = period*10*UINT64_C(60000);
  return PAYMENT_PROFILE_OK;
}

static int
renew_valid(const payment_profile_renew_t *r)
{
  uint64_t first, activation;
  if (renew_schedule(r->period, &first, &activation) ||
      r->first_round != first || r->activation_ms != activation ||
      !payment_profile_ids_valid(r->ids))
    return PAYMENT_PROFILE_ERR_SEQUENCE;
  return PAYMENT_PROFILE_OK;
}

int
payment_profile_renew_check(const payment_profile_renew_t *r,
                           const payment_profile_policy_t *policy,
                           uint64_t expected_period, const uint8_t terms[32],
                           const uint8_t parent[32])
{
  if (!r || !terms || !parent)
    return PAYMENT_PROFILE_ERR_BODY;
  if (renew_valid(r) || r->period != expected_period)
    return PAYMENT_PROFILE_ERR_SEQUENCE;
  if (!policy_valid(policy))
    return PAYMENT_PROFILE_ERR_POLICY;
  if (tor_memneq(r->terms, terms, 32))
    return PAYMENT_PROFILE_ERR_TERMS;
  if (tor_memneq(r->parent, parent, 32))
    return PAYMENT_PROFILE_ERR_PARENT;
  if (r->period >= policy->max_periods ||
      r->activation_ms > UINT64_MAX-10*UINT64_C(60000) ||
      r->activation_ms+10*UINT64_C(60000) > policy->max_age_ms)
    return PAYMENT_PROFILE_ERR_POLICY;
  return PAYMENT_PROFILE_OK;
}

static int
renewed_valid(const payment_profile_renewed_t *r)
{
  uint64_t first, activation;
  if (r->status > 9 ||
      (r->status == 1 && r->elapsed_ms < r->activation_ms))
    return PAYMENT_PROFILE_ERR_BODY;
  /* BAD_SEQUENCE may echo invalid period/first_round with zero safe clocks. */
  if (r->status == 7 && !r->activation_ms && !r->admit_before_ms)
    return PAYMENT_PROFILE_OK;
  if (renew_schedule(r->period, &first, &activation) ||
      r->first_round != first || r->activation_ms != activation ||
      r->admit_before_ms != activation-PAYMENT_PROFILE_ROUND_MS)
    return PAYMENT_PROFILE_ERR_BODY;
  return PAYMENT_PROFILE_OK;
}

static int
started_valid(const payment_profile_started_t *s)
{
  if (s->state > 7 || !s->revision)
    return PAYMENT_PROFILE_ERR_BODY;
  if (s->state == 0 &&
      (!all_zero(s->terms, 32) || !all_zero(s->allocation, 32)))
    return PAYMENT_PROFILE_ERR_BODY;
  if (s->state <= 2 && (s->round || s->elapsed_ms ||
      s->round_remaining_ms || s->enforcement_remaining_ms))
    return PAYMENT_PROFILE_ERR_BODY;
  if (s->state == 3 || s->state == 4) {
    if (s->round != s->elapsed_ms/PAYMENT_PROFILE_ROUND_MS+1 ||
        s->setup_remaining_ms ||
        s->round_remaining_ms != PAYMENT_PROFILE_ROUND_MS-
                                 s->elapsed_ms%PAYMENT_PROFILE_ROUND_MS)
      return PAYMENT_PROFILE_ERR_BODY;
    /* An accepted hard age may end before the nominal round. The origin
     * validates the tighter bound against its pinned policy context. */
    if (s->state == 3 && s->enforcement_remaining_ms >
        s->round_remaining_ms + PAYMENT_PROFILE_ROUND_MS)
      return PAYMENT_PROFILE_ERR_BODY;
    if (s->state == 4 &&
        s->enforcement_remaining_ms > s->round_remaining_ms)
      return PAYMENT_PROFILE_ERR_BODY;
  }
  if ((s->state == 5 || s->state == 6) &&
      (s->round_remaining_ms || s->enforcement_remaining_ms ||
       s->setup_remaining_ms))
    return PAYMENT_PROFILE_ERR_BODY;
  return PAYMENT_PROFILE_OK;
}

/* Parse after authentication; caller clears the temporary on any error. */
static int
parse_body(payment_profile_message_t *m, const uint8_t *w)
{
#define COPY(field, offset, n) memcpy((field), w+(offset), (n))
  switch (m->command) {
    case PAYMENT_PROFILE_RENEW: {
      payment_profile_renew_t *r = &m->u.renew;
      if (w[1] || w[18] != 10)
        return PAYMENT_PROFILE_ERR_HEADER;
      r->period = read_be(w+2, 8); r->first_round = read_be(w+10, 8);
      COPY(r->nonce, 19, 16); r->activation_ms = read_be(w+35, 8);
      if (read_be(w+43, 4) != PAYMENT_PROFILE_ROUND_MS)
        return PAYMENT_PROFILE_ERR_SEQUENCE;
      COPY(r->terms, 47, 32); COPY(r->parent, 79, 32);
      COPY(r->ids, 111, 320);
      return renew_valid(r);
    }
    case PAYMENT_PROFILE_RENEWED: {
      payment_profile_renewed_t *r = &m->u.renewed;
      if (w[1] || w[3] || w[156] != 10 || !all_zero(w+157, 274))
        return PAYMENT_PROFILE_ERR_HEADER;
      r->status = w[2]; r->period = read_be(w+4, 8);
      COPY(r->nonce, 12, 16); COPY(r->request_digest, 28, 32);
      COPY(r->allocation, 60, 32); r->elapsed_ms = read_be(w+92, 8);
      r->activation_ms = read_be(w+100, 8);
      r->admit_before_ms = read_be(w+108, 8);
      COPY(r->terms, 116, 32); r->first_round = read_be(w+148, 8);
      if (r->status >= 2 && !all_zero(r->allocation, 32))
        return PAYMENT_PROFILE_ERR_BODY;
      return renewed_valid(r);
    }
    case PAYMENT_PROFILE_COMMIT: {
      payment_profile_commit_t *c = &m->u.commit;
      if (w[1] || !all_zero(w+105, 326))
        return PAYMENT_PROFILE_ERR_HEADER;
      COPY(c->nonce, 2, 16); COPY(c->allocation, 73, 32);
      return payment_profile_policy_decode(&c->policy, w+18, 55);
    }
    case PAYMENT_PROFILE_COMMITTED: {
      payment_profile_committed_t *c = &m->u.committed;
      c->status = w[1]; COPY(c->nonce, 2, 16);
      COPY(c->request_digest, 18, 32); COPY(c->terms, 50, 32);
      COPY(c->allocation, 82, 32);
      c->setup_remaining_ms = (uint32_t)read_be(w+114, 4);
      if (!all_zero(w+118, 313))
        return PAYMENT_PROFILE_ERR_HEADER;
      if (c->status > 5 || (c->status &&
          (!all_zero(c->terms, 32) || !all_zero(c->allocation, 32))) ||
          (c->status >= 4 && c->setup_remaining_ms))
        return PAYMENT_PROFILE_ERR_BODY;
      return PAYMENT_PROFILE_OK;
    }
    case PAYMENT_PROFILE_START_STATUS: {
      payment_profile_start_t *s = &m->u.start;
      s->action = w[1]; COPY(s->nonce, 2, 16);
      COPY(s->terms, 18, 32); COPY(s->allocation, 50, 32);
      s->round = read_be(w+82, 8);
      if (!all_zero(w+90, 341))
        return PAYMENT_PROFILE_ERR_HEADER;
      if (s->action > 1 || s->round != (s->action ? 0 : 1))
        return PAYMENT_PROFILE_ERR_BODY;
      return PAYMENT_PROFILE_OK;
    }
    case PAYMENT_PROFILE_STARTED_STATUS: {
      payment_profile_started_t *s = &m->u.started;
      s->state = w[1]; COPY(s->nonce, 2, 16);
      COPY(s->request_digest, 18, 32); COPY(s->terms, 50, 32);
      COPY(s->allocation, 82, 32); s->round = read_be(w+114, 8);
      s->elapsed_ms = read_be(w+122, 8);
      s->round_remaining_ms = (uint32_t)read_be(w+130, 4);
      s->enforcement_remaining_ms = (uint32_t)read_be(w+134, 4);
      s->setup_remaining_ms = (uint32_t)read_be(w+138, 4);
      s->revision = read_be(w+142, 8);
      if (!all_zero(w+150, 281))
        return PAYMENT_PROFILE_ERR_HEADER;
      return started_valid(s);
    }
    default:
      return PAYMENT_PROFILE_ERR_HEADER;
  }
#undef COPY
}

int
payment_profile_decode(payment_profile_message_t *out,
                       payment_profile_command_t command,
                       const uint8_t *wire, size_t len,
                       const uint8_t key[32], const uint8_t binding[32])
{
  if (!out)
    return PAYMENT_PROFILE_ERR_BODY;
  memset(out, 0, sizeof(*out));
  if (!wire || len != PAYMENT_PROFILE_WIRE_LEN)
    return PAYMENT_PROFILE_ERR_LENGTH;
  if (!key || !binding)
    return PAYMENT_PROFILE_ERR_BODY;
  if (wire[0] != 1)
    return PAYMENT_PROFILE_ERR_HEADER;
  uint8_t mac[32];
  int r = message_mac(mac, command, wire, key, binding);
  if (r)
    return r;
  int bad_mac = tor_memneq(mac, wire+PAYMENT_PROFILE_BODY_LEN, 32);
  memwipe(mac, 0, sizeof(mac));
  if (bad_mac)
    return PAYMENT_PROFILE_ERR_MAC;
  payment_profile_message_t tmp = {0};
  tmp.command = command;
  r = parse_body(&tmp, wire);
  if (r == PAYMENT_PROFILE_OK)
    *out = tmp;
  memwipe(&tmp, 0, sizeof(tmp));
  return r;
}

int
payment_profile_encode(uint8_t *out, size_t len,
                       const payment_profile_message_t *m,
                       const uint8_t key[32], const uint8_t binding[32])
{
  if (!out || len != PAYMENT_PROFILE_WIRE_LEN)
    return PAYMENT_PROFILE_ERR_LENGTH;
  memset(out, 0, len);
  if (!m || !key || !binding)
    return PAYMENT_PROFILE_ERR_BODY;
  uint8_t w[PAYMENT_PROFILE_WIRE_LEN] = {0};
  w[0] = 1;
#define COPY(offset, field, n) memcpy(w+(offset), (field), (n))
  int r = PAYMENT_PROFILE_OK;
  switch (m->command) {
    case PAYMENT_PROFILE_RENEW: {
      const payment_profile_renew_t *p = &m->u.renew;
      write_be(w+2, p->period, 8); write_be(w+10, p->first_round, 8);
      w[18] = 10; COPY(19, p->nonce, 16);
      write_be(w+35, p->activation_ms, 8);
      write_be(w+43, PAYMENT_PROFILE_ROUND_MS, 4);
      COPY(47, p->terms, 32); COPY(79, p->parent, 32);
      COPY(111, p->ids, 320);
      break;
    }
    case PAYMENT_PROFILE_RENEWED: {
      const payment_profile_renewed_t *p = &m->u.renewed;
      w[2] = p->status; write_be(w+4, p->period, 8);
      COPY(12, p->nonce, 16); COPY(28, p->request_digest, 32);
      COPY(60, p->allocation, 32); write_be(w+92, p->elapsed_ms, 8);
      write_be(w+100, p->activation_ms, 8);
      write_be(w+108, p->admit_before_ms, 8);
      COPY(116, p->terms, 32); write_be(w+148, p->first_round, 8);
      w[156] = 10;
      break;
    }
    case PAYMENT_PROFILE_COMMIT: {
      const payment_profile_commit_t *p = &m->u.commit;
      COPY(2, p->nonce, 16); COPY(73, p->allocation, 32);
      r = payment_profile_policy_encode(w+18, 55, &p->policy);
      break;
    }
    case PAYMENT_PROFILE_COMMITTED: {
      const payment_profile_committed_t *p = &m->u.committed;
      w[1] = p->status; COPY(2, p->nonce, 16);
      COPY(18, p->request_digest, 32); COPY(50, p->terms, 32);
      COPY(82, p->allocation, 32); write_be(w+114, p->setup_remaining_ms, 4);
      break;
    }
    case PAYMENT_PROFILE_START_STATUS: {
      const payment_profile_start_t *p = &m->u.start;
      w[1] = p->action; COPY(2, p->nonce, 16);
      COPY(18, p->terms, 32); COPY(50, p->allocation, 32);
      write_be(w+82, p->round, 8);
      break;
    }
    case PAYMENT_PROFILE_STARTED_STATUS: {
      const payment_profile_started_t *p = &m->u.started;
      w[1] = p->state; COPY(2, p->nonce, 16);
      COPY(18, p->request_digest, 32); COPY(50, p->terms, 32);
      COPY(82, p->allocation, 32); write_be(w+114, p->round, 8);
      write_be(w+122, p->elapsed_ms, 8);
      write_be(w+130, p->round_remaining_ms, 4);
      write_be(w+134, p->enforcement_remaining_ms, 4);
      write_be(w+138, p->setup_remaining_ms, 4);
      write_be(w+142, p->revision, 8);
      break;
    }
    default:
      r = PAYMENT_PROFILE_ERR_HEADER;
  }
#undef COPY
  payment_profile_message_t checked = {0};
  checked.command = m->command;
  if (!r)
    r = parse_body(&checked, w);
  if (!r)
    r = message_mac(w+PAYMENT_PROFILE_BODY_LEN, m->command, w, key, binding);
  if (!r)
    memcpy(out, w, sizeof(w));
  memwipe(&checked, 0, sizeof(checked));
  memwipe(w, 0, sizeof(w));
  return r;
}

int
payment_profile_parse_capability(uint8_t terms[55],
                                 payment_capability_kind_t kind,
                                 int argc, const char *const *argv)
{
  uint8_t decoded[55];
  payment_profile_policy_t policy;
  if (!terms) return -1;
  memset(terms, 0, 55);
  if (argc < 1 || !argv || !argv[0] || !argv[0][0]) return -1;
  if (argv[0][0] == '0' && argv[0][1]) return -1;
  for (const char *p = argv[0]; *p; ++p)
    if (*p < '0' || *p > '9') return -1;
  if (strcmp(argv[0], "1")) return 0;
  if (kind == PAYMENT_CAPABILITY_FREE) {
    return argc == 4 && !strcmp(argv[1], "2") &&
      !strcmp(argv[2], "128") && !strcmp(argv[3], "600000") ? 1 : -1;
  }
  const char *hex;
  if (kind == PAYMENT_CAPABILITY_START) {
    if (argc != 6 || strcmp(argv[1], "226") || strcmp(argv[2], "227") ||
        strcmp(argv[3], "228") || strcmp(argv[4], "229")) return -1;
    hex = argv[5];
  } else if (kind == PAYMENT_CAPABILITY_RENEW) {
    if (argc != 4 || strcmp(argv[1], "224") || strcmp(argv[2], "225"))
      return -1;
    hex = argv[3];
  } else return -1;
  if (strlen(hex) != 110) return -1;
  for (size_t i = 0; i < 110; ++i) {
    unsigned value;
    if (hex[i] >= '0' && hex[i] <= '9') value = hex[i] - '0';
    else if (hex[i] >= 'a' && hex[i] <= 'f') value = hex[i] - 'a' + 10;
    else return -1;
    if (!(i % 2)) decoded[i/2] = (uint8_t)(value << 4);
    else decoded[i/2] |= (uint8_t)value;
  }
  if (payment_profile_policy_decode(&policy, decoded, sizeof(decoded)) != 0)
    return -1;
  memcpy(terms, decoded, sizeof(decoded));
  return 1;
}
