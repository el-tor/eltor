// src/feature/payment/payment_util.h
#ifndef PAYMENTS_UTILS_H
#define PAYMENTS_UTILS_H

#define PAYMENT_PREIMAGE_SIZE (64 + 14 + 1) // Size of the preimage + prefix eltor_preimage + 1 (64 + 14 + 1)
#define PAYMENT_PAYHASH_SIZE (64 + 13 + 1) // Size of the preimage + prefix eltor_payhash + 1 (64 + 13 + 1)

#include <stddef.h>

void payment_util_hex_to_bytes(const char* hex, unsigned char* bytes, size_t bytes_len);
int payment_util_verify_preimage(const char* preimage_hex, const char* payhash_hex);
void payment_util_get_preimage_from_torrc(char *eltor_preimage, char *eltor_payhash, int hop_num);
void payment_util_get_preimage_from_circ(char *eltor_preimage, char *eltor_payhash, char *preimage, char *payhash);

int payment_util_has_paid(const char *contact_info, const uint8_t *payload, size_t payload_len);

#endif // PAYMENTS_UTILS_H