/**
 * \file control_extendpaidcircuit.c
 * \brief EXTENDPAIDCIRCUIT 0
 *        relay_fingerprint_1 handshake_payment_hash + handshake_preimage + payment_id_hash_round1 + payment_id_hash_round2 + ...payment_id_hash_round10
 *        relay_fingerprint_2 handshake_payment_hash + handshake_preimage + payment_id_hash_round1 + payment_id_hash_round2 + ...payment_id_hash_round10 
 *        relay_fingerprint_3 handshake_payment_hash + handshake_preimage + payment_id_hash_round1 + payment_id_hash_round2 + ...payment_id_hash_round10
 */


/** Circuit Building Process (Function Chain)
* --------------------------------------------
* 
* src/core/or/circuitbuild.c:2678-2699 - circuit_handle_first_hop(circ)
*   → src/core/or/circuitbuild.c:394-430 - onion_populate_cpath(circ)
*     → src/core/or/circuitbuild.c:505-538 - onion_extend_cpath(circ)
*       → src/core/or/circuitbuild.c:845-864 - circuit_send_first_onion_skin(circ) 
*         → src/feature/payment/payment_util.c:320-343 - payment_util_get_first_hop_payhash(circ)
*           → src/feature/payment/payment_util.c:280-316 - payment_util_get_payhash_from_struct(circ, 1)
*             → src/feature/payment/relay_payments.c:250-268 - relay_payments_find_by_index(payments, 0)
*         → src/core/crypto/onion.c:162-189 - onion_skin_create() [creates handshake with payment]
*           → src/core/crypto/onion_ntor_v3.c:456-493 - create_onion_skin_ntor_v3_with_payment()
*             → src/core/crypto/onion_ntor_v3.c:126-134 - ntor3_derivate_secret_with_payment()
*               → [includes payment hash in CREATE/EXTEND2 cell]
*   → src/core/or/circuitbuild.c:2712-2731 - circuit_send_first_onion_skin(circ)
*     → src/core/or/command.c:1243-1271 - connection_or_send_cell(link, cell)
*       → src/core/or/connection_or.c:1842-1860 - connection_or_write_cell_to_buf()
* 
*/


/** Relay Side (Function Chain)
* ------------------------------
* 
* src/core/or/command.c:1345-1382 - command_process_cell(cell_t *cell)
*   → src/core/or/circuit.c:724-743 - circuit_receive(circ, cell)
*     → src/feature/relay/circuitbuild_relay.c:126-177 - command_process_create_cell(circ, cell)
*       → src/core/crypto/onion_fast.c:287-312 - onion_skin_server_handshake() [for fast handshake]
*       → src/core/crypto/onion_ntor_v3.c:512-559 - onion_skin_server_handshake_ntor_v3() [for ntor]
*         → src/feature/payment/payment_extract.c:67-95 - extract_payment_hash_from_cell()
*           → [payment hash extracted from handshake]
*         → src/feature/payment/payment_validate.c:126-174 - validate_payment_hash()
*           → src/feature/payment/payment_rpc.c:88-123 - verify_payment_hash_with_rpc()
*             → [validates payment hash against expected value from RPC]
*
*/

/** Payment Structs
* ------------------------------
* 
* src/feature/control/control_extendpaidcircuit.c:151-170 - handle_control_extendpaidcircuit()
*   → Parses payment lines from controller command
*   → src/feature/payment/relay_payments.c:94-110 - relay_payments_new() [creates structured payments]
*   → src/feature/payment/payment_util.c:460-498 - payment_util_parse_payment_line() [parses each line]
*   → src/feature/payment/relay_payments.c:126-131 - relay_payments_add_item() [adds to collection]
*   → Stores data in origin_circuit_t->relay_payments and origin_circuit_t->payhashes
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
#include "feature/nodelist/describe.h"
#include "feature/payment/relay_payments.h"
#include "feature/payment/payment_util.h"
#include "feature/payment/relay_payments.h"

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
  smartlist_split_string(lines, body, "\n", SPLIT_SKIP_SPACE | SPLIT_IGNORE_BLANK, 0);

  if (smartlist_len(lines) == 0) {
    control_write_endreply(conn, 512, "No router specifications provided");
    goto done;
  }

  // Create circuit if circ_id is "0", otherwise get the circuit
  if (zero_circ) {
    circ = origin_circuit_init(intended_purpose, 0);
    if (!circ) {
      control_write_endreply(conn, 551, "Couldn't create circuit");
      goto done;
    }
    circ->first_hop_from_controller = 1;
    log_debug(LD_CONTROL, "Created new circuit for EXTENDPAIDCIRCUIT");
  } else {
    // TODO handle better to avoid crashing
    uint32_t id;
    id = (uint32_t) tor_parse_ulong(circ_id, 10, 0, UINT32_MAX, NULL, NULL);
    if (!id) {
      control_printf_endreply(conn, 552, "Invalid circuit ID \"%s\"", circ_id);
      goto done;
    }
    
    circ = circuit_get_by_global_id(id);
    if (!circ || circ->base_.marked_for_close) {
      control_printf_endreply(conn, 552, "Unknown circuit \"%s\"", circ_id);
      goto done;
    }
    log_debug(LD_CONTROL, "Found existing circuit %s for EXTENDPAIDCIRCUIT", circ_id);
  }

  circ->any_hop_from_controller = 1;

  // Concatenate payment hashes into single string with newlines
  // Each payhash is ~768 chars (one for each relay, and 12 hashes concatinated), so allocate enough space
  // i.e payhashes is this concatinated "handshake_payment_hash + handshake_preimage + payment_id_hash_round1 + payment_id_hash_round2 + ...payment_id_hash_round10"
  char *payhashes = tor_malloc_zero(smartlist_len(lines) * 1024);

  // TODO new structure for relay payments, need to implement
  relay_payments_t *relay_payments = relay_payments_new();
  //    relay_payments = [{fingerprint: "", handshake_payment_hash: "", handshake_preimage: "", payhashes: "", wire_format: "eltor_payhash+payment_id_hash_round1+payment_id_hash_round2+...payment_id_hash_round10"}];
  
  // Process each line to extract fingerprint and payhashes
  SMARTLIST_FOREACH_BEGIN(lines, char *, line) {
    smartlist_t *tokens = smartlist_new();
    smartlist_split_string(tokens, line, " ", SPLIT_SKIP_SPACE | SPLIT_IGNORE_BLANK, 0);
    
    if (smartlist_len(tokens) != 2) {
      log_debug(LD_CONTROL, "Invalid line format: %s", line);
      SMARTLIST_FOREACH(tokens, char *, tok, tor_free(tok)); // avoid mem leak free the individual tokens in addition to the smartlist:
      smartlist_free(tokens);
      continue;
    }
    
    const char *fingerprint = smartlist_get(tokens, 0);
    const char *payhash = smartlist_get(tokens, 1);

    // NEW Use parser instead of manual steps
    relay_payment_item_t *payment_item = payment_util_parse_payment_line(line);
    if (!payment_item) {
      log_warn(LD_CONTROL, "Invalid payment line: %s", line);
      SMARTLIST_FOREACH(tokens, char *, tok, tor_free(tok)); // free each token
      smartlist_free(tokens);
      continue;
    }
    // Add to our structured collection
    relay_payments_add_item(relay_payments, payment_item);
    // Log the parsed payment_item fields for debugging
    log_relay_payment(payment_item);
    
    // Add this payhash to our combined payment hashes string
    if (strlen(payhashes) > 0) {
      strlcat(payhashes, "\n", smartlist_len(lines) * 1024);
    }
    strlcat(payhashes, payhash, smartlist_len(lines) * 1024);
    
    log_debug(LD_CONTROL, "Processing hop: fingerprint=%s, payhash length=%zu",
              fingerprint, strlen(payhash));
    
    // Validate the fingerprint
    const node_t *node = node_get_by_nickname(fingerprint, 0);
    if (!node) {
      control_printf_endreply(conn, 552, "No such router \"%s\"", fingerprint);
      smartlist_free(tokens);
      tor_free(payhashes);
      relay_payments_free(relay_payments);
      goto done;
    }
    if (!node_has_preferred_descriptor(node, zero_circ)) {
      control_printf_endreply(conn, 552, "No descriptor for \"%s\"", fingerprint);
      smartlist_free(tokens);
      tor_free(payhashes);
      relay_payments_free(relay_payments); 
      goto done;
    }
    smartlist_add(nodes, (void*)node);
    
    smartlist_free(tokens);
  } SMARTLIST_FOREACH_END(line);
  
  if (!smartlist_len(nodes)) {
    control_write_endreply(conn, 512, "No valid nodes provided");
    tor_free(payhashes);
    relay_payments_free(relay_payments);
    goto done;
  }

  // Store the payment hash in the circuit
  tor_free(circ->payhashes);
  circ->payhashes = payhashes;
  log_info(LD_CONTROL, "ELTOR circuit payment hash total length: %zu", strlen(payhashes));

  tor_free(circ->relay_payments);
  circ->relay_payments = relay_payments;

  // Append hops to circuit path
  bool first_node = zero_circ;
  SMARTLIST_FOREACH(nodes, const node_t *, node, {
    extend_info_t *info = extend_info_from_node(node, first_node, true);
    if (!info) {
      // Don't assert - it's normal for any hop to potentially fail
      log_warn(LD_CONTROL,
               "controller tried to connect to %s node (%s) that lacks a suitable "
               "descriptor, or which doesn't have any "
               "addresses allowed by the firewall configuration; "
               "circuit marked for closing.",
               first_node ? "first" : "non-first",
               node_describe(node));
      circuit_mark_for_close(TO_CIRCUIT(circ), END_CIRC_REASON_CONNECTFAILED);
      control_write_endreply(conn, 551, "Couldn't extend circuit: missing descriptor or valid address");
      goto done;
    }
    circuit_append_new_exit(circ, info);
    if (circ->build_state->desired_path_len > 1) {
      circ->build_state->onehop_tunnel = 0;
    }
    extend_info_free(info);
    first_node = 0;
  });

  // Handle new circuit creation vs extending existing circuit
  if (zero_circ) {
    // Handle new circuit creation
    int err_reason = 0;
    if ((err_reason = circuit_handle_first_hop(circ)) < 0) {
      circuit_mark_for_close(TO_CIRCUIT(circ), -err_reason);
      control_write_endreply(conn, 551, "Couldn't start circuit");
      goto done;
    }
  } else {
    // TODO test this
    // Handle extending existing circuit
    if (circ->base_.state == CIRCUIT_STATE_OPEN ||
        circ->base_.state == CIRCUIT_STATE_GUARD_WAIT) {
      int err_reason = 0;
      circuit_set_state(TO_CIRCUIT(circ), CIRCUIT_STATE_BUILDING);
      if ((err_reason = circuit_send_next_onion_skin(circ)) < 0) {
        log_info(LD_CONTROL,
                 "circuit_send_next_onion_skin failed; circuit marked for closing.");
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
  if (relay_payments) {
    if (!circ || circ->relay_payments != relay_payments) {
      relay_payments_free(relay_payments);
    }
  }
  
  // More robust cleanup for payhashes
  if (payhashes) {
    if (!circ || circ->payhashes != payhashes) {
      tor_free(payhashes);
    }
  }
  return 0;
}
