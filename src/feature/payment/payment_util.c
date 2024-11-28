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
payment_util_verify_preimage(const char *preimage_hex,
                              const char *payhash_hex)
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
payment_util_get_preimage_from_torrc(char *eltor_preimage, char *eltor_payhash,
                                     int hop_num)
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
  const char prefix[] = "eltor_preimage";
  snprintf(eltor_preimage, 64 + 14 + 1, "%s%s", prefix, eltor_preimage_raw);

  // Prefix the PayHash string
  const char prefixPayHash[] = "eltor_payhash";
  snprintf(eltor_payhash, PAYMENT_PAYHASH_SIZE, "%s%s", prefixPayHash,
           eltor_payhash_raw);
}

void
payment_util_get_preimage_from_circ(char *eltor_preimage, char *eltor_payhash, char *preimage, char *payhash)
{
  // Ensure the input buffers and circuit are valid
  // tor_assert(eltor_preimage);
  // tor_assert(eltor_payhash);
  // tor_assert(preimage);
  // tor_assert(payhash);

  if (!preimage) {
    log_warn(LD_CONFIG, "Failed to read preimage");
    return;
  }
  if (!payhash) {
    log_warn(LD_CONFIG, "Failed to read payhash");
    return;
  }


  // Define buffer sizes
  const size_t raw_size = 64;
  const size_t prefix_size = 14; // Length of "eltor_preimage"
  const size_t total_size = raw_size + prefix_size + 1; // +1 for null terminator

  // 1. Parse Preimage
  char eltor_preimage_raw[raw_size + 1] = {0}; // null terminator
  strncpy(eltor_preimage_raw, preimage, raw_size);
  eltor_preimage_raw[raw_size] = '\0'; // Ensure null termination

  // 2. Parse Payhash
  char eltor_payhash_raw[raw_size + 1] = {0}; // null terminator
  strncpy(eltor_payhash_raw, payhash, raw_size);
  eltor_payhash_raw[raw_size] = '\0'; // Ensure null termination

  // 3. Prefix the Preimage string
  const char prefix[] = "eltor_preimage";
  snprintf(eltor_preimage, total_size, "%s%s", prefix, eltor_preimage_raw);

  // 4. Prefix the PayHash string
  const char prefixPayHash[] = "eltor_payhash";
  snprintf(eltor_payhash, total_size, "%s%s", prefixPayHash, eltor_payhash_raw);
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