/**
 * \file control_extendpaidcircuit.c
 * \brief EXTENDPAIDCIRCUIT 0
 *        fingerprint paymentidhash 
 *        fingerprint paymentidhash 
 *        fingerprint paymentidhash
 */

#define CONTROL_EVENTS_PRIVATE
#define CONTROL_MODULE_PRIVATE
#define CONTROL_GETINFO_PRIVATE

#define CONTROL_MODULE_PRIVATE
#define CONTROL_CMD_PRIVATE
#define CONTROL_EVENTS_PRIVATE

#include "core/or/or.h"
#include "app/config/config.h"
#include "lib/confmgt/confmgt.h"
#include "app/main/main.h"
#include "core/mainloop/connection.h"
#include "core/or/circuitbuild.h"
#include "core/or/circuitlist.h"
#include "core/or/circuituse.h"
#include "core/or/connection_edge.h"
#include "core/or/circuitstats.h"
#include "core/or/extendinfo.h"
#include "feature/client/addressmap.h"
#include "feature/client/dnsserv.h"
#include "feature/client/entrynodes.h"
#include "feature/control/control.h"
#include "feature/control/control_auth.h"
#include "feature/control/control_cmd.h"
#include "feature/control/control_hs.h"
#include "feature/control/control_events.h"
#include "feature/control/control_getinfo.h"
#include "feature/control/control_proto.h"
#include "feature/control/control_extendpaidcircuit.h"
#include "feature/hs/hs_control.h"
#include "feature/hs/hs_service.h"
#include "feature/nodelist/nodelist.h"
#include "feature/nodelist/routerinfo.h"
#include "feature/nodelist/routerlist.h"
#include "feature/rend/rendcommon.h"
#include "lib/crypt_ops/crypto_rand.h"
#include "lib/crypt_ops/crypto_util.h"
#include "lib/encoding/confline.h"
#include "lib/encoding/kvline.h"

#include "core/or/cpath_build_state_st.h"
#include "core/or/entry_connection_st.h"
#include "core/or/origin_circuit_st.h"
#include "core/or/socks_request_st.h"
#include "feature/control/control_cmd_args_st.h"
#include "feature/control/control_connection_st.h"
#include "feature/nodelist/node_st.h"
#include "feature/nodelist/routerinfo_st.h"

#include "app/config/statefile.h"

#ifdef HAVE_UNISTD_H
#  include <unistd.h>
#endif

#ifndef _WIN32
#  include <pwd.h>
#endif

const control_cmd_syntax_t extendpaidcircuit_syntax = {
  .min_args = 1,
  .max_args = 1,
  .want_cmddata = true, // Enable multiline data
  .accept_keywords = true,
  .kvline_flags = KV_OMIT_VALS
};

/** Helper function: Return the circuit with ID <b>circ_id</b>, or NULL
 * if no such circuit exists. */
static origin_circuit_t *
get_circ(const char *circ_id)
{
  uint32_t id;
  origin_circuit_t *circ;
  
  if (!strcasecmp(circ_id, "0"))
    return NULL;

  id = (uint32_t) tor_parse_ulong(circ_id, 10, 0, UINT32_MAX, NULL, NULL);
  if (!id)
    return NULL;
  
  circ = circuit_get_by_global_id(id);
  if (!circ || circ->base_.marked_for_close)
    return NULL;
  
  return circ;
}

/** Called when we get an EXTENDPAIDCIRCUIT message. Try to extend the listed
 * circuit with payment hash data, and report success or failure. */
int 
handle_control_extendpaidcircuit(control_connection_t *conn,
                                 const control_cmd_args_t *args)
{
  smartlist_t *nodes = smartlist_new();
  origin_circuit_t *circ = NULL;
  uint8_t intended_purpose = CIRCUIT_PURPOSE_C_GENERAL;
  const char *circ_id = smartlist_get(args->args, 0);
  bool zero_circ = !strcmp("0", circ_id);

  const char *body = args->cmddata;

  log_debug(LD_CONTROL, "EXTENDPAIDCIRCUIT: %s", body);

  // Parse multiline input
  smartlist_t *lines = smartlist_new();
  smartlist_split_string(lines, body, "\n",
                         SPLIT_SKIP_SPACE | SPLIT_IGNORE_BLANK, 0);

  if (zero_circ) {
    // Creating a new circuit
    circ = origin_circuit_init(intended_purpose, 0);
    if (!circ) {
      control_write_endreply(conn, 551, "Couldn't create circuit");
      goto done;
    }
    circ->first_hop_from_controller = 1;
  } else {
    // Extending an existing circuit
    circ = get_circ(circ_id);
    if (!circ) {
      control_printf_endreply(conn, 552, "Unknown circuit \"%s\"", circ_id);
      goto done;
    }
  }

  circ->any_hop_from_controller = 1;

  // Concatenate payhash into payhashes
  // Each payhash is 768 chars, 3 rounds = 3*768 + null terminator = 2305

  // Use a static buffer large enough for safety
  static char payhashes[4096];
  payhashes[0] = '\0'; // Reset buffer at the start of each call

  // Process each line
  SMARTLIST_FOREACH_BEGIN(lines, char *, line) {
    log_debug(LD_CONTROL, "EXTENDPAIDCIRCUIT Line: %s", line);

    smartlist_t *tokens = smartlist_new();
    smartlist_split_string(tokens, line, " ",
                           SPLIT_SKIP_SPACE | SPLIT_IGNORE_BLANK, 0);

    log_debug(LD_CONTROL, "EXTENDPAIDCIRCUIT Token Length: %d", smartlist_len(tokens));

    if (smartlist_len(tokens) != 2) {
      connection_printf_to_buf(conn, "512 Invalid line format: %s\r\n", line);
      smartlist_free(tokens);
      continue;
    }

    const char *fingerprint = smartlist_get(tokens, 0);
    const char *payhash = smartlist_get(tokens, 1);

    // Add the payhash to our combined payment hashes string
    if (strlen(payhashes) > 0) {
      // Add a newline between entries if not the first one
      strlcat(payhashes, "\n", sizeof(payhashes));
    }
    strlcat(payhashes, payhash, sizeof(payhashes));

    log_debug(LD_CONTROL, "Line: fingerprint = %s", fingerprint);
    log_debug(LD_CONTROL, "Payhash length = %zu", strlen(payhash));

    // Validate the fingerprint
    const node_t *node = node_get_by_nickname(fingerprint, 0);
    if (!node) {
      control_printf_endreply(conn, 552, "No such router \"%s\"", fingerprint);
      smartlist_free(tokens);
      goto done;
    }
    if (!node_has_preferred_descriptor(node, zero_circ)) {
      control_printf_endreply(conn, 552, "No descriptor for \"%s\"", fingerprint);
      smartlist_free(tokens);
      goto done;
    }
    smartlist_add(nodes, (void*)node);

    smartlist_free(tokens);
  } SMARTLIST_FOREACH_END(line);

  if (!smartlist_len(nodes)) {
    control_write_endreply(conn, 512, "No valid nodes provided");
    goto done;
  }

  log_info(LD_CONTROL, "ELTOR circuit payment hash total length: %zu", strlen(payhashes));

  // Store the payment hash in the circuit
  tor_free(circ->payhash);
  circ->payhash = tor_strdup(payhashes);

  bool first_node = zero_circ;
  SMARTLIST_FOREACH(nodes, const node_t *, node,
  {
    extend_info_t *info = extend_info_from_node(node, first_node, true);
    if (!info) {
      tor_assert_nonfatal(first_node);
      log_warn(LD_CONTROL,
               "controller tried to connect to a node that lacks a suitable "
               "descriptor, or which doesn't have any "
               "addresses that are allowed by the firewall configuration; "
               "circuit marked for closing.");
      circuit_mark_for_close(TO_CIRCUIT(circ), -END_CIRC_REASON_CONNECTFAILED);
      control_write_endreply(conn, 551, "Couldn't start circuit");
      goto done;
    }
    circuit_append_new_exit(circ, info);
    if (circ->build_state->desired_path_len > 1) {
      circ->build_state->onehop_tunnel = 0;
    }
    extend_info_free(info);
    first_node = 0;
  });

  if (zero_circ) {
    // Handle new circuit creation
    int err_reason = 0;
    if ((err_reason = circuit_handle_first_hop(circ)) < 0) {
      circuit_mark_for_close(TO_CIRCUIT(circ), -err_reason);
      control_write_endreply(conn, 551, "Couldn't start circuit");
      goto done;
    }
  } else {
    // Handle extending existing circuit
    if (circ->base_.state == CIRCUIT_STATE_OPEN ||
        circ->base_.state == CIRCUIT_STATE_GUARD_WAIT) {
      int err_reason = 0;
      circuit_set_state(TO_CIRCUIT(circ), CIRCUIT_STATE_BUILDING);
      if ((err_reason = circuit_send_next_onion_skin(circ)) < 0) {
        log_info(LD_CONTROL,
                 "send_next_onion_skin failed; circuit marked for closing.");
        circuit_mark_for_close(TO_CIRCUIT(circ), -err_reason);
        control_write_endreply(conn, 551, "Couldn't send onion skin");
        goto done;
      }
    } else {
      control_write_endreply(conn, 551, 
                           "Circuit is not in a state that can be extended");
      goto done;
    }
  }

  control_printf_endreply(conn, 250, "EXTENDED %lu",
                          (unsigned long)circ->global_identifier);
  if (zero_circ) /* send a 'launched' event, for completeness */
    circuit_event_status(circ, CIRC_EVENT_LAUNCHED, 0);
  
done:
  SMARTLIST_FOREACH(lines, char *, cp, tor_free(cp));
  smartlist_free(lines);
  smartlist_free(nodes);
  return 0;
}
