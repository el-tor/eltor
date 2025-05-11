// src/feature/payment/payment_util.c
#include "orconfig.h"
#include <openssl/sha.h>
#include <string.h>
#include <stdio.h>
#include "app/config/config.h"
#include "lib/confmgt/confmgt.h"
#include "lib/log/log.h"
#include "feature/payment/payment_util.h"
#include "core/or/origin_circuit_st.h"
#include "feature/control/control_events.h"
#include "core/or/origin_circuit_st.h"
#include "core/or/crypt_path_st.h"
#include "feature/payment/relay_payments.h"
#include "core/or/circuituse.h"


// Function to convert a hex string to a byte array
void
payment_util_hex_to_bytes(const char *hex, unsigned char *bytes,
                          size_t bytes_len)
{
  for (size_t i = 0; i < bytes_len; ++i) {
    sscanf(hex + 2 * i, "%2hhx", &bytes[i]);
  }
}

// Function to verify if the preimage matches the given payment hash
int
payment_util_verify_preimage(const char *preimage_hex, const char *payhash_hex)
{
  unsigned char preimage[32];
  unsigned char payhash[32];
  unsigned char hash[SHA256_DIGEST_LENGTH];

  // Convert hex strings to byte arrays
  payment_util_hex_to_bytes(preimage_hex, preimage, 32);
  payment_util_hex_to_bytes(payhash_hex, payhash, 32);

  // Compute the SHA-256 hash of the preimage
  SHA256(preimage, 32, hash);

  // Compare the computed hash with the provided payment hash
  return memcmp(hash, payhash, SHA256_DIGEST_LENGTH) == 0;
}

// Function to get preimage and payhash from torrc and prefix them
void
payment_util_get_preimage_from_torrc(char *eltor_payhash, int hop_num)
{
  char eltor_preimage_raw[64 + 1] = {0}; // null terminator
  char eltor_payhash_raw[64 + 1] = {0}; // null terminator

  // read the torrc to get the updated preimage value
  char *torrc_contents = load_torrc_from_disk(NULL, 0);
  if (!torrc_contents) {
    log_warn(LD_CONFIG, "Failed to read torrc file");
    return;
  }

  // 1. Get preimage
  char preimage_key[32];
  snprintf(preimage_key, sizeof(preimage_key), "ElTorPreimageHop%d", hop_num);
  char *preimage_value = strstr(torrc_contents, preimage_key);
  if (preimage_value) {
    preimage_value += strlen(preimage_key);
    while (*preimage_value == ' ') {
      preimage_value++;
    }
    strncpy(eltor_preimage_raw, preimage_value, 64);
    eltor_preimage_raw[64] = '\0'; // Ensure null termination
    log_info(LD_CIRC, "ElTorPreimageHop%d: %s", hop_num, eltor_preimage_raw);
  } else {
    log_warn(LD_CONFIG, "Preimage key %s not found in torrc", preimage_key);
  }

  // 2. Get payhash
  char payhash_key[32];
  snprintf(payhash_key, sizeof(payhash_key), "ElTorPayHashHop%d", hop_num);
  char *payhash_value = strstr(torrc_contents, payhash_key);
  if (payhash_value) {
    payhash_value += strlen(payhash_key);
    while (*payhash_value == ' ') {
      payhash_value++;
    }
    strncpy(eltor_payhash_raw, payhash_value, 64);
    eltor_payhash_raw[64] = '\0'; // Ensure null termination
    log_info(LD_CIRC, "ElTorPayHashHop%d: %s", hop_num, eltor_payhash_raw);
  } else {
    log_warn(LD_CONFIG, "PayHash key %s not found in torrc", payhash_key);
  }

  // Free the allocated memory for torrc_contents
  tor_free(torrc_contents);

  // Prefix the Preimage string
  // const char prefix[] = "eltor_preimage";
  // snprintf(eltor_preimage, 64 + 14 + 1, "%s%s", prefix, eltor_preimage_raw);

  // Prefix the PayHash string
  const char prefixPayHash[] = "eltor_payhash";
  snprintf(eltor_payhash, PAYMENT_PAYHASH_SIZE, "%s%s", prefixPayHash,
           eltor_payhash_raw);
}

void
payment_util_get_payhash_from_circ(char *eltor_payhash, char *payhash,
                                   int hop_num)
{
  // Ensure the input buffers and circuit are valid
  // tor_assert(eltor_preimage);
  // tor_assert(eltor_payhash);
  // tor_assert(preimage);
  // tor_assert(payhash);

  // if (!preimage) {
  //   log_warn(LD_CONFIG, "Failed to read preimage");
  //   return;
  // }
  if (!payhash) {
    log_warn(LD_CONFIG, "Failed to read payhash");
    return;
  }

  // Define buffer sizes
  const size_t raw_size =
      2304; // handshake_fee_payment_hash+handshake_fee_preimage+10_payment_ids_concatinated
  const size_t prefix_size = 13; // Length of "eltor_payhash"
  const size_t total_size =
      raw_size + prefix_size + 1; // +1 for null terminator

  // 1. Parse Preimage
  // char eltor_preimage_raw[raw_size + 1];
  // memset(eltor_preimage_raw, 0, sizeof(eltor_preimage_raw)); // null
  // terminator strncpy(eltor_preimage_raw, preimage, raw_size);
  // eltor_preimage_raw[raw_size] = '\0'; // Ensure null termination

  // 2. Parse Payhash
  char eltor_payhash_raw[raw_size + 1];
  memset(eltor_payhash_raw, 0, sizeof(eltor_payhash_raw)); // null terminator

  // Calculate offset based on hop_num (1-based)
  size_t offset = (hop_num - 1) * 768;
  if (offset + 768 > raw_size) {
    log_warn(LD_CONFIG, "Invalid hop_num or payhash too short");
    eltor_payhash_raw[0] = '\0';
  } else {
    strncpy(eltor_payhash_raw, payhash + offset, 768);
    eltor_payhash_raw[768] = '\0'; // Ensure null termination
    log_info(LD_CONFIG, "eltor_payhash_raw (hop %d): %s", hop_num,
             eltor_payhash_raw);
  }

  // 3. Prefix the Preimage string
  // const char prefix[] = "eltor_preimage";
  // snprintf(eltor_preimage, total_size, "%s%s", prefix, eltor_preimage_raw);

  // 4. Prefix the PayHash string
  const char prefixPayHash[] = "eltor_payhash";
  snprintf(eltor_payhash, total_size, "%s%s", prefixPayHash,
           eltor_payhash_raw);
}

// Function to check if payment has been made
int
payment_util_has_paid(const char *contact_info, const uint8_t *payload,
                      size_t payload_len)
{
  if (!contact_info) {
    log_info(LD_APP,
             "No BOLT 12 provided in ContactInfo. No payment required.");
    return 1;
  }

  // Check for preimage
  const char *prefix = "eltor_preimage";
  const char *prefixPayHash = "eltor_payhash";
  size_t nlen = strlen(prefix);
  size_t plen = strlen(prefixPayHash);
  const void *found = tor_memmem(payload, payload_len, prefix, nlen);
  const void *foundPayHash =
      tor_memmem(payload, payload_len, prefixPayHash, plen);

  if (found && foundPayHash) {
    size_t index = (const uint8_t *)found - payload;
    size_t indexPayHash = (const uint8_t *)foundPayHash - payload;
    if (index + nlen + 64 <= payload_len &&
        indexPayHash + plen + 64 <= payload_len) {
      char preimage[64 + 1]; // null-terminated string
      memcpy(preimage, payload + index + nlen, 64);
      preimage[64] = '\0'; // Null-terminate the string
      log_info(LD_APP, "ElTorRelay: %s, Preimage: %s", get_options()->Nickname,
               preimage);

      // Check for payhash
      char payhash[64 + 1]; // null-terminated string
      memcpy(payhash, payload + indexPayHash + plen, 64);
      payhash[64] = '\0'; // Null-terminate the string
      log_info(LD_APP, "ElTorRelay: %s, PayHash: %s", get_options()->Nickname,
               payhash);

      // Verify preimage against the payment hash
      if (payment_util_verify_preimage(preimage, payhash)) {
        log_info(LD_APP, "ElTor 200");
        return 1;
      } else {
        log_info(LD_APP, "ElTor L402");
      }
    }
  }

  return 0;
}

// Function to check if a payment id hash was passed
int
payment_util_has_payment_id_hash(const uint8_t *payload, size_t payload_len)
{
  const char *prefixPayHash = "eltor_payhash";
  size_t plen = strlen(prefixPayHash);

  // Log relay nickname and circuit ID
  log_notice(
      LD_APP,
      "ELTOR RELAY %s: Checking for payment hash in cell payload (len=%zu)",
      get_options()->Nickname, payload_len);

  // Search for the prefix in the payload
  const void *foundPayHash =
      tor_memmem(payload, payload_len, prefixPayHash, plen);
  if (foundPayHash) {
    size_t indexPayHash = (const uint8_t *)foundPayHash - payload;
    log_notice(LD_APP,
               "ELTOR RELAY %s: Found payhash at offset %zu in payload",
               get_options()->Nickname, indexPayHash);

    // Make sure we have enough room to get the hash
    size_t remaining = payload_len - (indexPayHash + plen);
    if (remaining < 1) {
      log_warn(LD_APP, "ELTOR RELAY %s: Found prefix but no room for payhash",
               get_options()->Nickname);
      return 0;
    }

    // Extract a reasonable amount of the hash (up to 768 bytes)
    size_t copy_len = MIN(768, remaining);

    char payhash[769]; // 768 + null terminator
    memcpy(payhash, (const char *)payload + indexPayHash + plen, copy_len);
    payhash[copy_len] = '\0';

    log_notice(LD_APP,
               "ELTOR RELAY %s: Successfully extracted payhash (length=%zu)",
               get_options()->Nickname, strlen(payhash));
    log_notice(LD_APP, "ELTOR RELAY %s: Payment hash first 50 chars: %.50s...",
               get_options()->Nickname, payhash);

    // control_event_payment_id_hash_received(payhash, global_id);
    return 1;
  } else {
    log_notice(LD_APP, "ELTOR RELAY %s: PayHash prefix not found in payload",
               get_options()->Nickname);

    // Add additional debugging to check for any string that looks like a
    // payment hash
    log_debug(LD_APP, "ELTOR RELAY %s: Full payload hex dump: %s",
              get_options()->Nickname, hex_str(payload, payload_len));
    return 0;
  }
}

/**
 * Helper function to get the payment hash for a specific hop in a circuit.
 *
 * @param circ The origin circuit containing the payment hash
 * @param hop The crypt path for the hop we're extending to
 * @return Static buffer containing the payment hash for this hop, or NULL if
 * not found
 */
const char *
payment_util_get_hop_payhash(origin_circuit_t *circ, crypt_path_t *hop)
{
  if (!circ || !circ->payhashes || !hop)
    return NULL;

  // Find the hop number
  int hop_num = 0;
  for (crypt_path_t *cur = circ->cpath; cur != NULL; cur = cur->next) {
    hop_num++;
    if (cur == hop) {
      break;
    }
    if (cur->next == circ->cpath) {
      break; // Full loop without finding hop
    }
  }

  // No match found or invalid hop
  if (hop_num <= 0) {
    log_warn(LD_GENERAL, "ELTOR: Could not determine hop number");
    return NULL;
  }

  log_info(LD_GENERAL, "ELTOR: Extracting payment hash for hop %d", hop_num);

  // Allocate a buffer for the extracted payment hash
  static char extracted_payhash[PAYMENT_PAYHASH_SIZE];
  memset(extracted_payhash, 0, sizeof(extracted_payhash));

  // Use existing function to extract the payment hash for this hop
  payment_util_get_payhash_from_circ(extracted_payhash, circ->payhashes,
                                     hop_num);

  if (strlen(extracted_payhash) > 0) {
    log_info(LD_GENERAL,
             "ELTOR: Found payment hash for hop %d (first 20 chars): %.20s...",
             hop_num, extracted_payhash);
    return extracted_payhash;
  } else {
    log_info(LD_GENERAL, "ELTOR: No payment hash found for hop %d", hop_num);
    return NULL;
  }
}

/**
 * Helper function to get the payment hash for the first hop in a circuit.
 * This is simpler than the general hop function since we always use hop_num
 * = 1.
 *
 * @param circ The origin circuit containing the payment hash
 * @return Static buffer containing the payment hash for the first hop, or NULL
 * if not found
 */
const char *
payment_util_get_first_hop_payhash(origin_circuit_t *circ)
{
  if (!circ) return NULL;

  uint8_t purpose = circ->base_.purpose;
  if (circuit_purpose_is_hidden_service(purpose)) {
    // TODO Skip payments for hidden services for now, just use dummy values
    return "d5ddf78f461c67569046f8291e789163b8e13c9cc737552133abfadddcf0f054824601029cfe46aa978decd83e969c11bc17968a60ab96bf688e1352369105bb3e098bc3a359fd663a4545990b6cad089a85708a2cd2b323be78d2fbd32112b6ab64f093beee01533673dd75e27d4ad7626935ec0260be4efd40e2b51c80bf64472912c110796f1d83b2292f3652de52429249e1fd2ef82b64f7df8ea7e745f93d7265a70203ade5868599e24316227464592b1fd68a5d48e7953abd5e7ea76c93c90ad2db89593875ba121bb9177ca4d585a7c434013480c5d41669c5d75531727f5c952c1117a4d4869c0c14fa9e0780401c0ae1582a3410f199a3a03eb1f3a94073e0f0b47be9747b0619bb6c16cc225207e78c5bab155b90183a8e3477a07787dc4a27ff6abe69de62c80b0f23422cb540ed8947bc0987fe51310b8648695fae894b3c2cf45549342cac1c12607a9329163511a92be780203d9acc2be484589e63b904fb99a617852312844ef80b56d28ae253122e289c1080968e830192";
  }

  if (!circ->payhashes) return NULL;
  static char extracted_payhash[PAYMENT_PAYHASH_SIZE];
  memset(extracted_payhash, 0, sizeof(extracted_payhash));

  // Extract the first hop's payment hash (hop_num = 1)
  payment_util_get_payhash_from_circ(extracted_payhash, circ->payhashes, 1);

  if (strlen(extracted_payhash) > 0) {
    log_info(LD_CIRC, "ELTOR: Found first hop payment hash (length: %zu)",
             strlen(extracted_payhash));
    return extracted_payhash;
  } else {
    log_info(LD_CIRC, "ELTOR: No payment hash found for first hop");
    return NULL;
  }
}

/**
 * Parse a raw payment line into a structured relay_payment_item_t.
 * Format: "fingerprint handshake_payment_hash(64) + handshake_preimage(64) +
 * payhashes"
 *
 * @param line The raw line to parse
 * @return A newly allocated relay_payment_item_t or NULL on error
 */
relay_payment_item_t *
payment_util_parse_payment_line(const char *line)
{
  if (!line || !strlen(line))
    return NULL;

  relay_payment_item_t *item = relay_payment_item_new();
  if (!item)
    return NULL;

  // Split line by space to get fingerprint and payload
  char *space = strchr(line, ' ');
  if (!space) {
    log_warn(LD_CONTROL,
             "ELTOR: Invalid payment line format (no space found)");
    relay_payment_item_free(item);
    return NULL;
  }

  // Extract fingerprint (part before space)
  size_t fp_len = space - line;
  item->fingerprint = tor_malloc_zero(fp_len + 1);
  memcpy(item->fingerprint, line, fp_len);

  // Get the payload after the space
  const char *payload = space + 1;
  size_t payload_len = strlen(payload);

  // Check if payload is long enough
  if (payload_len < 128) { // At least 64+64 chars for hash and preimage
    log_warn(LD_CONTROL, "ELTOR: Invalid payment payload (too short: %zu)",
             payload_len);
    relay_payment_item_free(item);
    return NULL;
  }

  // Extract handshake payment hash (first 64 chars)
  item->handshake_payment_hash = tor_malloc_zero(65);
  memcpy(item->handshake_payment_hash, payload, 64);

  // Extract handshake preimage (next 64 chars)
  item->handshake_preimage = tor_malloc_zero(65);
  memcpy(item->handshake_preimage, payload + 64, 64);

  // Extract payhashes (remaining chars)
  size_t payhashes_len = payload_len - 128;
  if (payhashes_len > 0) {
    item->payhashes = tor_malloc_zero(payhashes_len + 1);
    memcpy(item->payhashes, payload + 128, payhashes_len);
  } else {
    item->payhashes = tor_strdup("");
  }

  // Set wire_format as "eltor_payhash" + payload
  const char *prefix = "eltor_payhash";
  size_t prefix_len = strlen(prefix);
  item->wire_format = tor_malloc_zero(prefix_len + payload_len + 1);
  memcpy(item->wire_format, prefix, prefix_len);
  memcpy(item->wire_format + prefix_len, payload, payload_len);

  log_debug(
      LD_CONTROL,
      "ELTOR: Parsed payment line for %s (hash: %.10s..., preimage: %.10s...)",
      item->fingerprint, item->handshake_payment_hash,
      item->handshake_preimage);

  return item;
}
