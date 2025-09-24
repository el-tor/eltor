/**
 * \file control_teardowncircuit.c
 * \brief Implementation of TEARDOWNCIRCUIT control command for deferred circuit teardown.
 *
 * This command allows for logging circuit teardown requests to a database or file
 * for later processing, which is useful when the circuit reference may become 
 * invalid before teardown can occur.
 **/

#define CONTROL_MODULE_PRIVATE
#define CONTROL_CMD_PRIVATE
#define CONTROL_EVENTS_PRIVATE

#define CHANNEL_OBJECT_PRIVATE

#include "core/or/or.h"
#include "app/config/config.h"
#include "core/or/circuitlist.h"
#include "core/or/channel.h"
#include "core/or/channeltls.h"
#include "lib/encoding/confline.h"
#include "lib/encoding/kvline.h"
#include "feature/control/control_cmd.h"
#include "feature/control/control_events.h"
#include "feature/control/control_proto.h"
#include "feature/control/control_teardowncircuit.h"

#include "core/or/circuit_st.h"
#include "core/or/or_circuit_st.h"
#include "core/or/origin_circuit_st.h"
#include "core/or/or_connection_st.h"
#include "feature/control/control_cmd_args_st.h"
#include "feature/control/control_connection_st.h"

#include <time.h>

/** Teardown modes for circuit processing */
typedef enum {
  TEARDOWN_MODE_DEFERRED = 0,  /**< Log for later processing */
  TEARDOWN_MODE_IMMEDIATE = 1, /**< Tear down immediately */
  TEARDOWN_MODE_LOG_ONLY = 2   /**< Only log, no teardown */
} teardown_mode_t;

/** Check if circuit is open and active (worth logging for teardown) */
static int
circuit_is_open_and_active(const circuit_t *circ)
{
  if (!circ) return 0;
  
  // Check if circuit is marked for close
  if (circ->marked_for_close) {
    return 0;
  }
  
  // Check circuit state - only log if it's in an active state
  switch (circ->state) {
    case CIRCUIT_STATE_OPEN:
    case CIRCUIT_STATE_BUILDING:
    case CIRCUIT_STATE_ONIONSKIN_PENDING:
      return 1;  // Circuit is open/active
    
    case CIRCUIT_STATE_CHAN_WAIT:
      return 1;  // Still building, consider it active
    
    default:
      return 0;  // Circuit is closing or in invalid state
  }
}

/** Structure to hold circuit teardown information for logging */
typedef struct circuit_teardown_info_t {
  uint32_t circuit_id;                    /**< Circuit ID */
  char peer_identity[DIGEST_LEN];         /**< RSA identity of peer */
  char peer_ed25519[ED25519_PUBKEY_LEN];  /**< Ed25519 identity of peer */
  char peer_address[INET6_ADDRSTRLEN];    /**< IP address string */
  uint16_t peer_port;                     /**< Port number */
  char reason[64];                        /**< Reason for teardown */
  time_t timestamp;                       /**< When teardown was requested */
  int is_origin;                          /**< 1 if origin circuit, 0 if OR circuit */
} circuit_teardown_info_t;

const control_cmd_syntax_t teardowncircuit_syntax = {
  .min_args = 1,
  .max_args = 2,
  .accept_keywords = true,
  .kvline_flags = KV_OMIT_VALS
};

/** Extract circuit information for teardown logging */
static void
extract_circuit_teardown_info(const circuit_t *circ, 
                              circuit_teardown_info_t *info,
                              const char *reason)
{
  if (!circ || !info) return;
  
  memset(info, 0, sizeof(*info));
  info->timestamp = time(NULL);
  info->is_origin = CIRCUIT_IS_ORIGIN(circ);
  
  if (reason) {
    strlcpy(info->reason, reason, sizeof(info->reason));
  } else {
    strlcpy(info->reason, "unknown", sizeof(info->reason));
  }
  
  if (CIRCUIT_IS_ORIGIN(circ)) {
    const origin_circuit_t *oc = CONST_TO_ORIGIN_CIRCUIT(circ);
    info->circuit_id = oc->global_identifier;
    
    // For origin circuits, there might not be a peer channel yet
    // if the circuit is still being built
    strlcpy(info->peer_address, "origin_circuit", sizeof(info->peer_address));
    info->peer_port = 0;
  } else {
    const or_circuit_t *or_circ = CONST_TO_OR_CIRCUIT(circ);
    info->circuit_id = or_circ->p_circ_id;
    
    // Get peer channel information
    const channel_t *p_chan = or_circ->p_chan;
    if (p_chan) {
      // Copy RSA identity
      memcpy(info->peer_identity, p_chan->identity_digest, DIGEST_LEN);
      
      // Copy Ed25519 identity if available
      if (!ed25519_public_key_is_zero(&p_chan->ed25519_identity)) {
        memcpy(info->peer_ed25519, p_chan->ed25519_identity.pubkey, 
               ED25519_PUBKEY_LEN);
      }
      
      // Get peer address
      tor_addr_t remote_addr;
      if (channel_get_addr_if_possible(p_chan, &remote_addr)) {
        tor_addr_to_str(info->peer_address, &remote_addr, 
                        sizeof(info->peer_address), 0);
        // Port information is not easily accessible from channel
        // We'll just set it to 0 for now
        info->peer_port = 0;
      }
    }
  }
}

/** Log circuit teardown request to file */
static void
log_circuit_teardown_to_file(const circuit_teardown_info_t *info)
{
  FILE *teardown_log = fopen("circuit_teardown.log", "a");
  if (!teardown_log) {
    log_warn(LD_CONTROL, "Failed to open circuit teardown log file");
    return;
  }
  
  char unique_id[128];
  tor_snprintf(unique_id, sizeof(unique_id), "circ_%u_%s_%ld",
               info->circuit_id, 
               info->is_origin ? "origin" : "or",
               (long)info->timestamp);
  
  fprintf(teardown_log, 
          "TEARDOWN_REQUESTED|%s|%u|%s|%s|%s|%u|%s|%ld|%d\n",
          unique_id,
          info->circuit_id,
          hex_str(info->peer_identity, DIGEST_LEN),
          hex_str(info->peer_ed25519, ED25519_PUBKEY_LEN),
          info->peer_address,
          info->peer_port,
          info->reason,
          (long)info->timestamp,
          info->is_origin);
  
  fclose(teardown_log);
  
  log_notice(LD_CONTROL, "ELTOR TEARDOWN: Logged circuit %s for teardown: %s",
             unique_id, info->reason);
}

/** Create JSON RPC payload for circuit teardown request */
static char *
create_teardown_rpc_payload(const circuit_teardown_info_t *info)
{
  char *payload = tor_malloc(2048);
  
  char unique_id[128];
  tor_snprintf(unique_id, sizeof(unique_id), "circ_%u_%ld",
               info->circuit_id, (long)info->timestamp);
  
  tor_snprintf(payload, 2048,
    "{"
    "\"jsonrpc\":\"2.0\","
    "\"method\":\"teardown_circuit\","
    "\"params\":{"
      "\"circuit_id\":%u,"
      "\"unique_id\":\"%s\","
      "\"peer_identity\":\"%s\","
      "\"peer_ed25519\":\"%s\","
      "\"peer_address\":\"%s\","
      "\"peer_port\":%u,"
      "\"reason\":\"%s\","
      "\"timestamp\":%ld,"
      "\"is_origin\":%s"
    "},"
    "\"id\":\"%s\""
    "}",
    info->circuit_id,
    unique_id,
    hex_str(info->peer_identity, DIGEST_LEN),
    hex_str(info->peer_ed25519, ED25519_PUBKEY_LEN),
    info->peer_address,
    info->peer_port,
    info->reason,
    (long)info->timestamp,
    info->is_origin ? "true" : "false",
    unique_id
  );
  
  return payload;
}

/** Helper to check if keyword flags are present */
static bool
teardown_config_lines_contain_flag(const config_line_t *lines, const char *flag)
{
  const config_line_t *line = config_line_find_case(lines, flag);
  return line && !strcmp(line->value, "");
}

/** Force immediate circuit destruction, bypassing normal cleanup delays */
static void
force_immediate_circuit_destruction(circuit_t *circ, int reason)
{
  if (!circ) return;
  
  // Force immediate marking for close with aggressive flags
  circ->marked_for_close = 1;
  circ->marked_for_close_reason = reason;
  
  // Remove circuit ID from global maps immediately
  circid_t circ_id = circ->n_circ_id;
  if (circ_id) {
    circuit_set_n_circid_chan(circ, 0, NULL);
  }
  
  // Force state to indicate circuit is non-functional
  circ->state = CIRCUIT_STATE_BUILDING; // Reset to building to break functionality
  
  // Call the standard mark for close but bypass normal cleanup delays
  circuit_mark_for_close(circ, reason);
}

// Public wrapper for external callers
void
eltor_force_immediate_circuit_destruction(circuit_t *circ, int reason)
{
  if (!circ) return;
  
  log_notice(LD_CONTROL, "ELTOR FORCE IMMEDIATE: Destroying circuit %u immediately due to missing payment hash", 
            CIRCUIT_IS_ORCIRC(circ) ? TO_OR_CIRCUIT(circ)->p_circ_id : 0);
  
  force_immediate_circuit_destruction(circ, reason);
}

/** Find circuit for teardown by ID and optional peer identity */
static circuit_t *
find_circuit_for_teardown(const char *circuit_id_str, const char *peer_identity_fingerprint)
{
  uint32_t circuit_id;
  int ok;
  
  circuit_id = (uint32_t) tor_parse_ulong(circuit_id_str, 10, 0, UINT32_MAX, &ok, NULL);
  if (!ok)
    return NULL;
  
  log_notice(LD_CONTROL, "TEARDOWN DEBUG: Parsed circuit_id=%u from string '%s'", 
            circuit_id, circuit_id_str);
  
  // If peer identity is provided, decode it
  char peer_identity[DIGEST_LEN];
  int have_peer_identity = 0;
    // Decode peer identity if provided
  if (peer_identity_fingerprint && strlen(peer_identity_fingerprint) == (size_t)(DIGEST_LEN * 2)) {
    if (base16_decode(peer_identity, DIGEST_LEN, peer_identity_fingerprint,
                      strlen(peer_identity_fingerprint)) == DIGEST_LEN) {      have_peer_identity = 1;
    }
  }
  
  // First try to find as origin circuit
  origin_circuit_t *origin_circ = circuit_get_by_global_id(circuit_id);
  if (origin_circ) {
    log_notice(LD_CONTROL, "TEARDOWN DEBUG: Found origin circuit with global_id=%u", circuit_id);
    return TO_CIRCUIT(origin_circ);
  }
  
  log_notice(LD_CONTROL, "TEARDOWN DEBUG: No origin circuit found, searching OR circuits");
  
  // Search for OR circuits
  SMARTLIST_FOREACH_BEGIN(circuit_get_global_list(), circuit_t *, circ) {
    if (!CIRCUIT_IS_ORIGIN(circ) && !circ->marked_for_close) {
      or_circuit_t *or_circ = TO_OR_CIRCUIT(circ);
      
      log_notice(LD_CONTROL, "TEARDOWN DEBUG: Checking OR circuit p_circ_id=%u, n_circ_id=%u against target=%u", 
                or_circ->p_circ_id, circ->n_circ_id, circuit_id);
      
      if (or_circ->p_circ_id == circuit_id || circ->n_circ_id == circuit_id) {
        // If peer identity is specified, verify it matches
        if (have_peer_identity && or_circ->p_chan) {
          if (tor_memeq(or_circ->p_chan->identity_digest, peer_identity, DIGEST_LEN)) {
            return circ;
          }
        } else if (!have_peer_identity) {
          // No peer identity specified, return first match
          return circ;
        }
      }
    }
  } SMARTLIST_FOREACH_END(circ);
  
  return NULL;
}

/** Called when we get a TEARDOWNCIRCUIT command */
int
handle_control_teardowncircuit(control_connection_t *conn,
                               const control_cmd_args_t *args)
{
  const char *circuit_id_str = smartlist_get(args->args, 0);
  const char *reason = "control_request";
  
  // Optional reason argument
  if (smartlist_len(args->args) >= 2) {
    reason = smartlist_get(args->args, 1);
  }
  
  // SPECIAL NUCLEAR OPTION: "ALL" destroys everything
  if (!strcasecmp(circuit_id_str, "ALL")) {
    log_notice(LD_CONTROL, "SPEC-COMPLIANT DOOMSDAY: Destroying all circuits according to Tor protocol");
    
    smartlist_t *global_list = circuit_get_global_list();
    int total_circuits = smartlist_len(global_list);
    int destroy_count = 0;
    
    log_notice(LD_CONTROL, "DOOMSDAY: Found %d circuits to destroy properly", total_circuits);
    
    // Create a copy of the circuit list to avoid modification during iteration
    smartlist_t *circuits_copy = smartlist_new();
    SMARTLIST_FOREACH_BEGIN(global_list, circuit_t *, circ) {
      smartlist_add(circuits_copy, circ);
    } SMARTLIST_FOREACH_END(circ);
    
    // Send DESTROY cells for each circuit according to Tor spec
    SMARTLIST_FOREACH_BEGIN(circuits_copy, circuit_t *, circ) {
      if (circ->marked_for_close) continue; // Skip already closing circuits
      
      destroy_count++;
      log_notice(LD_CONTROL, "DOOMSDAY: Destroying circuit %d/%d", destroy_count, total_circuits);
      
      // Send DESTROY cells according to circuit type
      if (CIRCUIT_IS_ORCIRC(circ)) {
        or_circuit_t *or_circ = TO_OR_CIRCUIT(circ);
        
        // Send DESTROY towards previous hop
        if (or_circ->p_chan && or_circ->p_circ_id) {
          log_debug(LD_CONTROL, "DOOMSDAY: DESTROY to P-channel for circuit_id=%u", or_circ->p_circ_id);
          channel_send_destroy(or_circ->p_circ_id, or_circ->p_chan, END_CIRC_REASON_REQUESTED);
        }
        
        // Send DESTROY towards next hop
        if (circ->n_chan && circ->n_circ_id) {
          log_debug(LD_CONTROL, "DOOMSDAY: DESTROY to N-channel for circuit_id=%u", circ->n_circ_id);
          channel_send_destroy(circ->n_circ_id, circ->n_chan, END_CIRC_REASON_REQUESTED);
        }
      } else {
        // Origin circuit - send DESTROY towards first hop
        if (circ->n_chan && circ->n_circ_id) {
          log_debug(LD_CONTROL, "DOOMSDAY: DESTROY for origin circuit_id=%u", circ->n_circ_id);
          channel_send_destroy(circ->n_circ_id, circ->n_chan, END_CIRC_REASON_REQUESTED);
        }
      }
      
      // Mark circuit for close using Tor's standard mechanism
      circuit_mark_for_close(circ, END_CIRC_REASON_REQUESTED);
      
    } SMARTLIST_FOREACH_END(circ);
    
    smartlist_free(circuits_copy);
    
    log_notice(LD_CONTROL, "DOOMSDAY COMPLETE: Sent DESTROY cells for %d circuits", destroy_count);
    
    control_printf_endreply(conn, 250, "OK SPEC-COMPLIANT DOOMSDAY: DESTROY cells sent for %d circuits", destroy_count);
    return 0;
  }
  
  // Optional peer identity for OR circuits
  const char *peer_identity = NULL;
  if (args->kwargs) {
    for (config_line_t *line = args->kwargs; line; line = line->next) {
      if (!strcasecmp(line->key, "PeerIdentity")) {
        peer_identity = line->value;
        break;
      }
    }
  }
  
  log_debug(LD_CONTROL, "TEARDOWNCIRCUIT: circuit_id=%s, reason=%s, peer_identity=%s",
            circuit_id_str, reason, peer_identity ? peer_identity : "none");
  
  // Debug: Print all kwargs
  if (args->kwargs) {
    log_notice(LD_CONTROL, "TEARDOWN DEBUG: Processing kwargs...");
    for (config_line_t *line = args->kwargs; line; line = line->next) {
      log_notice(LD_CONTROL, "TEARDOWN DEBUG: kwargs - key='%s', value='%s'", 
                line->key ? line->key : "NULL", 
                line->value ? line->value : "NULL");
    }
  } else {
    log_notice(LD_CONTROL, "TEARDOWN DEBUG: No kwargs provided");
  }
  
  // Check teardown mode options
  bool immediate = true;  // Always use immediate mode for aggressive teardown
  bool log_only = teardown_config_lines_contain_flag(args->kwargs, "LogOnly");
  bool force_immediate = teardown_config_lines_contain_flag(args->kwargs, "FORCE_IMMEDIATE");
  
  log_notice(LD_CONTROL, "TEARDOWN DEBUG: immediate=%s (forced), log_only=%s, force_immediate=%s", 
            immediate ? "true" : "false", log_only ? "true" : "false", 
            force_immediate ? "true" : "false");
  
  circuit_t *circ = find_circuit_for_teardown(circuit_id_str, peer_identity);
  
  log_notice(LD_CONTROL, "TEARDOWNCIRCUIT DEBUG: Looking for circuit %s, found: %s", 
            circuit_id_str, circ ? "YES" : "NO");
  
  if (!circ) {
    control_printf_endreply(conn, 552, "Unknown circuit \"%s\"", circuit_id_str);
    return 0;
  }
  
  // Only log if circuit is open/active
  if (circuit_is_open_and_active(circ)) {
    circuit_teardown_info_t teardown_info;
    extract_circuit_teardown_info(circ, &teardown_info, reason);
    log_circuit_teardown_to_file(&teardown_info);
    char *rpc_payload = create_teardown_rpc_payload(&teardown_info);
    log_notice(LD_CONTROL, "ELTOR RPC TEARDOWN: %s", rpc_payload);
    tor_free(rpc_payload);
    if (immediate && !log_only) {
      log_notice(LD_CONTROL, "SPEC-COMPLIANT TEARDOWN: Properly destroying circuit %s", circuit_id_str);
      
      // STEP 1: SEND PROPER DESTROY CELLS ACCORDING TO TOR SPEC
      // "To tear down a circuit completely, a relay or client sends a DESTROY cell to the
      //  adjacent nodes on that circuit, using the appropriate direction's circID."
      
      if (CIRCUIT_IS_ORCIRC(circ)) {
        or_circuit_t *or_circ = TO_OR_CIRCUIT(circ);
        
        // Send DESTROY cell towards the previous hop (P direction)
        if (or_circ->p_chan && or_circ->p_circ_id) {
          log_notice(LD_CONTROL, "SPEC TEARDOWN: Sending DESTROY to P-channel %"PRIu64" for circuit_id=%u", 
                    or_circ->p_chan->global_identifier, or_circ->p_circ_id);
          channel_send_destroy(or_circ->p_circ_id, or_circ->p_chan, END_CIRC_REASON_REQUESTED);
        }
        
        // Send DESTROY cell towards the next hop (N direction)  
        if (circ->n_chan && circ->n_circ_id) {
          log_notice(LD_CONTROL, "SPEC TEARDOWN: Sending DESTROY to N-channel %"PRIu64" for circuit_id=%u", 
                    circ->n_chan->global_identifier, circ->n_circ_id);
          channel_send_destroy(circ->n_circ_id, circ->n_chan, END_CIRC_REASON_REQUESTED);
        }
      } else {
        // Origin circuit - only send DESTROY towards the first hop
        if (circ->n_chan && circ->n_circ_id) {
          log_notice(LD_CONTROL, "SPEC TEARDOWN: Sending DESTROY for origin circuit to N-channel %"PRIu64" for circuit_id=%u", 
                    circ->n_chan->global_identifier, circ->n_circ_id);
          channel_send_destroy(circ->n_circ_id, circ->n_chan, END_CIRC_REASON_REQUESTED);
        }
      }
      
      // STEP 2: MARK CIRCUIT FOR CLOSE USING TOR'S STANDARD MECHANISM
      // "Upon receiving an outgoing DESTROY cell, a relay frees resources associated with
      //  the corresponding circuit."
      
      if (!circ->marked_for_close) {
        log_notice(LD_CONTROL, "SPEC TEARDOWN: Marking circuit for close via circuit_mark_for_close()");
        circuit_mark_for_close(circ, END_CIRC_REASON_REQUESTED);
      }
      
      // STEP 3: LET TOR'S EVENT LOOP HANDLE THE CLEANUP (unless FORCE_IMMEDIATE is requested)
      if (force_immediate) {
        log_notice(LD_CONTROL, "FORCE IMMEDIATE TEARDOWN: Bypassing normal cleanup delays");
        force_immediate_circuit_destruction(circ, END_CIRC_REASON_REQUESTED);
        control_printf_endreply(conn, 250, "OK FORCE IMMEDIATE TEARDOWN: Circuit %s destroyed immediately", circuit_id_str);
      } else {
        // Don't force anything - let Tor process the DESTROY cells and clean up naturally
        log_notice(LD_CONTROL, "SPEC TEARDOWN: Circuit teardown initiated according to Tor specification");
        control_printf_endreply(conn, 250, "OK SPEC-COMPLIANT TEARDOWN: DESTROY cells sent for circuit %s", circuit_id_str);
      }
    } else {
      control_printf_endreply(conn, 250, "OK Circuit %s teardown logged for processing", circuit_id_str);
    }
  } else {
    log_info(LD_CONTROL, "TEARDOWNCIRCUIT: Circuit %s is not open/active, skipping log.", circuit_id_str);
    control_printf_endreply(conn, 250, "OK Circuit %s is not open/active, not logged.", circuit_id_str);
  }
  
  return 0;
}
