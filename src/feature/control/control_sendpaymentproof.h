#ifndef TOR_CONTROL_SENDPAYMENTPROOF_H
#define TOR_CONTROL_SENDPAYMENTPROOF_H

#include "feature/control/control.h"
#include "lib/cc/compat_compiler.h"
#include "lib/cc/torint.h"

struct control_cmd_syntax_t;
struct control_cmd_args_t;
extern const struct control_cmd_syntax_t sendpaymentproof_syntax;

int handle_control_sendpaymentproof(control_connection_t *conn,  const control_cmd_args_t *args);

#endif // TOR_CONTROL_SENDPAYMENTPROOF_H

#define TOR_CONTROL_CMD_SENDPAYMENTPROOF "SENDPAYMENTPROOF"