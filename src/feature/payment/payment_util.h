// src/feature/payment/payment_util.h
#ifndef PAYMENTS_UTILS_H
#define PAYMENTS_UTILS_H

#define PAYMENT_PREIMAGE_SIZE (64 + 14 + 1) // Size of the preimage + prefix eltor_preimage + 1 (64 + 14 + 1)
#define PAYMENT_PAYHASH_SIZE (768 + 13 + 1) // Size of the payhash + prefix eltor_payhash + 1 (64 + 13 + 1)

#include <stddef.h>

struct origin_circuit_t;
struct crypt_path_t;

void payment_util_hex_to_bytes(const char* hex, unsigned char* bytes, size_t bytes_len);
int payment_util_verify_preimage(const char* preimage_hex, const char* payhash_hex);
void payment_util_get_preimage_from_torrc(char *eltor_payhash, int hop_num);
void payment_util_get_payhash_from_circ(char *eltor_payhash, char *payhash, int hop_num);
int payment_util_has_paid(const char *contact_info, const uint8_t *payload, size_t payload_len);
int payment_util_has_payment_id_hash(const uint8_t *payload, size_t payload_len);
const char *payment_util_get_hop_payhash(struct origin_circuit_t *circ, struct crypt_path_t *hop);

#endif // PAYMENTS_UTILS_H