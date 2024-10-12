// src/feature/payments/payment_utils.c
#include "orconfig.h"
#include <openssl/sha.h>
#include <string.h>
#include <stdio.h>

// Function to convert a hex string to a byte array
void payment_utils_hex_to_bytes(const char* hex, unsigned char* bytes, size_t bytes_len) {
  for (size_t i = 0; i < bytes_len; ++i) {
      sscanf(hex + 2 * i, "%2hhx", &bytes[i]);
  }
}

// Function to verify if the preimage matches the given payment hash
int payment_utils_verify_preimage(const char* preimage_hex, const char* payhash_hex) {
  unsigned char preimage[32];
  unsigned char payhash[32];
  unsigned char hash[SHA256_DIGEST_LENGTH];

  // Convert hex strings to byte arrays
  payment_utils_hex_to_bytes(preimage_hex, preimage, 32);
  payment_utils_hex_to_bytes(payhash_hex, payhash, 32);

  // Compute the SHA-256 hash of the preimage
  SHA256(preimage, 32, hash);

  // Compare the computed hash with the provided payment hash
  return memcmp(hash, payhash, SHA256_DIGEST_LENGTH) == 0;
}