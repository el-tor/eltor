/**
 * @file relay_payments.c
 * @brief Implementation of ElTor relay payment functionality
 **/

#include "feature/payment/relay_payments.h"
#include "feature/payment/relay_payments_st.h"
#include "lib/container/smartlist.h"
#include "lib/malloc/malloc.h"
#include "lib/log/log.h"
#include "lib/string/util_string.h"
#include "lib/string/printf.h"
#include "lib/log/util_bug.h"

/** Free all storage held by a relay payment item. */
void
relay_payment_item_free_(relay_payment_item_t *item)
{
  if (!item)
    return;

  tor_free(item->fingerprint);
  tor_free(item->handshake_payment_hash);
  tor_free(item->handshake_preimage);
  tor_free(item->payhashes);
  tor_free(item->wire_format);

  // Debug pattern - fill with unusual value before freeing
  memset(item, 0x5E,
         sizeof(relay_payment_item_t)); /* debug bad memory usage */

  tor_free(item);
}

/** Free a relay_payment_item_t along with all of its members. */
#define relay_payment_item_free(val) \
  FREE_AND_NULL(relay_payment_item_t, relay_payment_item_free_, (val))

/** Free all memory allocated for a relay_payments_t structure. */
void
relay_payments_free_(relay_payments_t *payments)
{
  if (!payments)
    return;

  // Free each item in the smartlist
  SMARTLIST_FOREACH(payments, relay_payment_item_t *, item,
                    relay_payment_item_free(item));
  smartlist_free(payments);
}

/** Free a relay_payments_t along with all its items. */
#define relay_payments_free(val) \
  FREE_AND_NULL(relay_payments_t, relay_payments_free_, (val))

/**
 * Create a new empty relay payment item
 */
relay_payment_item_t *
relay_payment_item_new(void)
{
  relay_payment_item_t *item = tor_malloc_zero(sizeof(relay_payment_item_t));
  return item;
}

/**
 * Create a new relay payments list
 */
relay_payments_t *
relay_payments_new(void)
{
  return smartlist_new();
}

/**
 * Add a payment item to a payments list
 */
void
relay_payments_add_item(relay_payments_t *payments, relay_payment_item_t *item)
{
  tor_assert(payments);
  tor_assert(item);
  smartlist_add(payments, item);
}

/**
 * Create a copy of a relay payment item
 */
relay_payment_item_t *
relay_payment_item_clone(const relay_payment_item_t *src)
{
  if (!src)
    return NULL;

  relay_payment_item_t *copy = relay_payment_item_new();

  if (src->fingerprint)
    copy->fingerprint = tor_strdup(src->fingerprint);

  if (src->handshake_payment_hash)
    copy->handshake_payment_hash = tor_strdup(src->handshake_payment_hash);

  if (src->handshake_preimage)
    copy->handshake_preimage = tor_strdup(src->handshake_preimage);

  if (src->payhashes)
    copy->payhashes = tor_strdup(src->payhashes);

  if (src->wire_format)
    copy->wire_format = tor_strdup(src->wire_format);

  return copy;
}

/**
 * Create a copy of an entire relay payments collection
 */
relay_payments_t *
relay_payments_clone(const relay_payments_t *src)
{
  if (!src)
    return NULL;

  relay_payments_t *copy = relay_payments_new();

  SMARTLIST_FOREACH_BEGIN (src, const relay_payment_item_t *, item) {
    relay_payment_item_t *item_copy = relay_payment_item_clone(item);
    if (item_copy) {
      relay_payments_add_item(copy, item_copy);
    }
  }
  SMARTLIST_FOREACH_END(item);

  return copy;
}

/**
 * Find a relay payment item by its fingerprint
 *
 * @param payments The collection to search
 * @param fingerprint The fingerprint to search for
 * @return The matching relay_payment_item_t or NULL if not found
 */
relay_payment_item_t *
relay_payments_find_by_fingerprint(const relay_payments_t *payments,
                                   const char *fingerprint)
{
  if (!payments || !fingerprint)
    return NULL;

  SMARTLIST_FOREACH_BEGIN (payments, relay_payment_item_t *, item) {
    if (item->fingerprint && !strcasecmp(item->fingerprint, fingerprint)) {
      return item;
    }
  }
  SMARTLIST_FOREACH_END(item);

  return NULL;
}

/**
 * Validate that a relay payment item has all required fields
 */
int
relay_payment_item_is_valid(const relay_payment_item_t *item)
{
  if (!item)
    return 0;

  if (!item->fingerprint || !strlen(item->fingerprint))
    return 0;

  if (!item->handshake_payment_hash || !strlen(item->handshake_payment_hash))
    return 0;

  /* payhashes and wire_format can be NULL if not needed */

  return 1;
}