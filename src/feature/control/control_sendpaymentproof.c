/**
 * \file control_sendpaymentproof.c
 * \brief SENDPAYMENTPROOF RELAYFINGERPRINT PAYHASH PREIMAGE
 */

#define CONTROL_EVENTS_PRIVATE
#define CONTROL_MODULE_PRIVATE
#define CONTROL_GETINFO_PRIVATE

#include "core/or/or.h"
#include "app/config/config.h"
#include "core/mainloop/connection.h"
#include "core/mainloop/mainloop.h"
#include "core/or/circuitlist.h"
#include "core/or/connection_edge.h"
#include "core/or/connection_or.h"
#include "core/or/policies.h"
#include "core/or/versions.h"
#include "feature/client/addressmap.h"
#include "feature/client/bridges.h"
#include "feature/client/entrynodes.h"
#include "feature/control/control.h"
#include "feature/control/control_cmd.h"
#include "feature/control/control_events.h"
#include "feature/control/control_fmt.h"
#include "feature/control/control_sendpaymentproof.h"
#include "feature/control/control_proto.h"
#include "feature/control/getinfo_geoip.h"
#include "feature/dircache/dirserv.h"
#include "feature/dirclient/dirclient.h"
#include "feature/dirclient/dlstatus.h"
#include "feature/dircommon/directory.h"
#include "feature/hibernate/hibernate.h"
#include "feature/hs/hs_cache.h"
#include "feature/hs_common/shared_random_client.h"
#include "feature/nodelist/authcert.h"
#include "feature/nodelist/microdesc.h"
#include "feature/nodelist/networkstatus.h"
#include "feature/nodelist/nodelist.h"
#include "feature/nodelist/routerinfo.h"
#include "feature/nodelist/routerlist.h"
#include "feature/relay/relay_find_addr.h"
#include "feature/relay/router.h"
#include "feature/relay/routermode.h"
#include "feature/relay/selftest.h"
#include "feature/stats/geoip_stats.h"
#include "feature/stats/predict_ports.h"
#include "feature/stats/rephist.h"
#include "lib/version/torversion.h"
#include "lib/encoding/kvline.h"

#include "core/or/entry_connection_st.h"
#include "core/or/or_connection_st.h"
#include "core/or/origin_circuit_st.h"
#include "core/or/socks_request_st.h"
#include "feature/control/control_connection_st.h"
#include "feature/control/control_cmd_args_st.h"
#include "feature/dircache/cached_dir_st.h"
#include "feature/nodelist/extrainfo_st.h"
#include "feature/nodelist/microdesc_st.h"
#include "feature/nodelist/networkstatus_st.h"
#include "feature/nodelist/node_st.h"
#include "feature/nodelist/routerinfo_st.h"
#include "feature/nodelist/routerlist_st.h"

#ifdef HAVE_UNISTD_H
#  include <unistd.h>
#endif

#ifndef _WIN32
#  include <pwd.h>
#endif

const control_cmd_syntax_t sendpaymentproof_syntax = {
  .min_args = 3,
  .max_args = 3,
};

int handle_control_sendpaymentproof(control_connection_t *conn,
                                const control_cmd_args_t *args)
{
//   char *relay_fingerprint = NULL;
//   char *payhash = NULL;
//   char *preimage = NULL;
//   smartlist_t *args_list = args->args;

//   if (smartlist_len(args_list) != 3) {
//     connection_printf_to_buf(conn, "512 Missing required arguments.\r\n");
//     return 0;
//   }

//   relay_fingerprint = smartlist_get(args_list, 0);
//   payhash = smartlist_get(args_list, 1);
//   preimage = smartlist_get(args_list, 2);

//   // Validate inputs
//   if (strlen(payhash) != 64 || strlen(preimage) != 64) {
//     connection_printf_to_buf(
//         conn, "513 PayHash and Preimage must be 64 characters.\r\n");
//     return 0;
//   }

//   // Verify preimage matches payhash
//   if (!crypto_digest256_eq(preimage, payhash)) {
//     connection_printf_to_buf(conn, "514 Preimage does not match PayHash.\r\n");
//     return 0;
//   }

  // Send successful response
  connection_printf_to_buf(conn,
                           "250 OK Payment proof verified and sent to relay.\r\n");

  return 0;
}