/* Copyright (c) 2026, The El Tor Project. */
/* See LICENSE for licensing information. */
#include "orconfig.h"
#include "feature/payment/payment_initial.h"
#include "feature/payment/payment_profile.h"
#include "lib/crypt_ops/crypto_util.h"
#include "lib/encoding/binascii.h"
#include <string.h>

void
payment_initial_clear(payment_initial_material_t *material)
{
  if (material) memwipe(material,0,sizeof(*material));
}

int
payment_initial_parse(payment_initial_material_t *out,
                        const uint8_t *payload, size_t len)
{
  static const char prefix[]="eltor_payhash";
  if (!out) return -1;
  payment_initial_clear(out);
  if (!payload || len!=sizeof(prefix)-1+768 ||
      memcmp(payload,prefix,sizeof(prefix)-1)) return -1;
  const uint8_t *hex=payload+sizeof(prefix)-1;
  for (size_t i=0;i<768;++i)
    if (!((hex[i]>='0' && hex[i]<='9') || (hex[i]>='a' && hex[i]<='f')))
      return -1;
  payment_initial_material_t parsed={0};
  if (base16_decode((char *)parsed.fee_hash,32,(const char *)hex,64)!=32 ||
      base16_decode((char *)parsed.ids,320,(const char *)hex+128,640)!=320 ||
      !payment_profile_ids_valid(parsed.ids)) {
    payment_initial_clear(&parsed);
    return -1;
  }
  parsed.valid=true;
  *out=parsed;
  payment_initial_clear(&parsed);
  return 0;
}
