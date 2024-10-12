// src/feature/payments/payment_utils.h
#ifndef PAYMENTS_UTILS_H
#define PAYMENTS_UTILS_H

#include <stddef.h>

void payment_utils_hex_to_bytes(const char* hex, unsigned char* bytes, size_t bytes_len);
int payment_utils_verify_preimage(const char* preimage_hex, const char* payhash_hex);

#endif // PAYMENTS_UTILS_H