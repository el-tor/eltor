/* Copyright (c) 2026, The El Tor Project. */
/* See LICENSE for licensing information. */
#include "orconfig.h"
#include "core/or/or.h"
#include "feature/payment/payment_initial.h"
#include "lib/encoding/binascii.h"
#include "test/test.h"

static void
test_initial_suffix(void *arg)
{
  (void)arg;
  char payload[782]; uint8_t bytes[384]={0};
  payment_initial_material_t material={0},zero={0};
  for (size_t i=0;i<10;++i) bytes[64+i*32]=(uint8_t)(i+1);
  memcpy(payload,"eltor_payhash",13);
  base16_encode(payload+13,sizeof(payload)-13,(char *)bytes,sizeof(bytes));
  for (char *p=payload+13;*p;++p) *p=TOR_TOLOWER(*p);
  tt_int_op(payment_initial_parse(&material,(uint8_t *)payload,781),OP_EQ,0);
  tt_assert(material.valid); tt_mem_op(material.ids,OP_EQ,bytes+64,320);
  tt_mem_op(material.fee_hash,OP_EQ,zero.fee_hash,32); /* dummy is not funding */
  tt_int_op(payment_initial_parse(&material,(uint8_t *)payload,782),OP_EQ,-1);
  tt_mem_op(&material,OP_EQ,&zero,sizeof(zero));
  payload[13+64]='x'; /* proof bytes are framed strictly too */
  tt_int_op(payment_initial_parse(&material,(uint8_t *)payload,781),OP_EQ,-1);
  payload[13+64]='0'; payload[13]='A';
  tt_int_op(payment_initial_parse(&material,(uint8_t *)payload,781),OP_EQ,-1);
  payload[13]='0'; memcpy(payload+13+128+64,payload+13+128,64);
  tt_int_op(payment_initial_parse(&material,(uint8_t *)payload,781),OP_EQ,-1);
  tt_mem_op(&material,OP_EQ,&zero,sizeof(zero));
 done: ;
}
struct testcase_t payment_initial_tests[]={
  {"suffix",test_initial_suffix,0,NULL,NULL}, END_OF_TESTCASES
};
