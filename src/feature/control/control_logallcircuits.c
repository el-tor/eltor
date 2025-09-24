/**
 * \file control_logallcircuits.c
 * \brief Implementation of LOGALLCIRCUITS control command for circuit inspection.
 *
 * This command logs all active circuits with their various IDs and states,
 * helping to correlate payment hashes with circuit identifiers for teardown.
 **/

#define CONTROL_MODULE_PRIVATE
#define CONTROL_CMD_PRIVATE

#include "core/or/or.h"
#include "core/or/circuitlist.h"
#include "core/or/channel.h"
#include "app/config/config.h"
#include "feature/control/control_cmd.h"
#include "feature/control/control_proto.h"
#include "feature/control/control_logallcircuits.h"

#include "core/or/circuit_st.h"
#include "core/or/or_circuit_st.h"
#include "core/or/origin_circuit_st.h"

/** LOGALLCIRCUITS command syntax */
const control_cmd_syntax_t logallcircuits_syntax = {
  .min_args = 0,
  .max_args = 0,
  .accept_keywords = false,
  .kvline_flags = 0
};

/** Get circuit state as a human-readable string */
static const char *
circuit_state_to_string_local(int state)
{
  switch (state) {
    case CIRCUIT_STATE_BUILDING: return "BUILDING";
    case CIRCUIT_STATE_ONIONSKIN_PENDING: return "ONIONSKIN_PENDING";
    case CIRCUIT_STATE_CHAN_WAIT: return "CHAN_WAIT";
    case CIRCUIT_STATE_GUARD_WAIT: return "GUARD_WAIT";
    case CIRCUIT_STATE_OPEN: return "OPEN";
    default: return "UNKNOWN";
  }
}

/** Get circuit purpose as a human-readable string */
static const char *
circuit_purpose_to_string_local(int purpose)
{
  switch (purpose) {
    case CIRCUIT_PURPOSE_C_GENERAL: return "C_GENERAL";
    case CIRCUIT_PURPOSE_C_INTRODUCING: return "C_INTRODUCING";
    case CIRCUIT_PURPOSE_C_ESTABLISH_REND: return "C_ESTABLISH_REND";
    case CIRCUIT_PURPOSE_C_REND_JOINED: return "C_REND_JOINED";
    case CIRCUIT_PURPOSE_C_REND_READY: return "C_REND_READY";
    case CIRCUIT_PURPOSE_C_REND_READY_INTRO_ACKED: return "C_REND_READY_INTRO_ACKED";
    case CIRCUIT_PURPOSE_S_ESTABLISH_INTRO: return "S_ESTABLISH_INTRO";
    case CIRCUIT_PURPOSE_S_INTRO: return "S_INTRO";
    case CIRCUIT_PURPOSE_S_CONNECT_REND: return "S_CONNECT_REND";
    case CIRCUIT_PURPOSE_S_REND_JOINED: return "S_REND_JOINED";
    case CIRCUIT_PURPOSE_TESTING: return "TESTING";
    case CIRCUIT_PURPOSE_CONTROLLER: return "CONTROLLER";
    case CIRCUIT_PURPOSE_OR: return "OR";
    default: return "UNKNOWN";
  }
}

/** Log detailed information about an OR circuit */
static void
log_or_circuit_info(control_connection_t *conn, const or_circuit_t *or_circ)
{
  const circuit_t *circ = TO_CIRCUIT(or_circ);
  const char *nickname = get_options()->Nickname ? get_options()->Nickname : "Unknown";
  
  control_printf_midreply(conn, 250, 
    "OR_CIRCUIT "
    "Nickname=%s "
    "N_CircuitID=%u "
    "P_CircuitID=%u "
    "State=%s "
    "Purpose=%s "
    "MarkedForClose=%s "
    "GlobalListIdx=%d "
    "P_ChanID=%"PRIu64" "
    "N_ChanID=%"PRIu64" "
    "PaymentHash=%s",
    nickname,
    circ->n_circ_id,
    or_circ->p_circ_id,
    circuit_state_to_string_local(circ->state),
    circuit_purpose_to_string_local(circ->purpose),
    circ->marked_for_close ? "true" : "false",
    circ->global_circuitlist_idx,
    or_circ->p_chan ? or_circ->p_chan->global_identifier : 0,
    circ->n_chan ? circ->n_chan->global_identifier : 0,
    or_circ->handshake_payment_hash ? or_circ->handshake_payment_hash : "none");
}

/** Log detailed information about an origin circuit */
static void
log_origin_circuit_info(control_connection_t *conn, const origin_circuit_t *orig_circ)
{
  const circuit_t *circ = TO_CIRCUIT(orig_circ);
  const char *nickname = get_options()->Nickname ? get_options()->Nickname : "Unknown";
  
  control_printf_midreply(conn, 250,
    "ORIGIN_CIRCUIT "
    "Nickname=%s "
    "N_CircuitID=%u "
    "State=%s "
    "Purpose=%s "
    "MarkedForClose=%s "
    "GlobalListIdx=%d "
    "N_ChanID=%"PRIu64" "
    "GlobalIdentifier=%u",
    nickname,
    circ->n_circ_id,
    circuit_state_to_string_local(circ->state),
    circuit_purpose_to_string_local(circ->purpose),
    circ->marked_for_close ? "true" : "false",
    circ->global_circuitlist_idx,
    circ->n_chan ? circ->n_chan->global_identifier : 0,
    orig_circ->global_identifier);
}

/** Called when we get a LOGALLCIRCUITS command */
int
handle_control_logallcircuits(control_connection_t *conn,
                              const control_cmd_args_t *args)
{
  (void)args; // Unused since we take no arguments
  
  int circuit_count = 0;
  smartlist_t *circuit_list = circuit_get_global_list();
  const char *nickname = get_options()->Nickname ? get_options()->Nickname : "Unknown";
  
  control_printf_midreply(conn, 250, "LOGALLCIRCUITS: Starting circuit enumeration for relay %s", nickname);
  
  // Iterate through all circuits using smartlist
  SMARTLIST_FOREACH_BEGIN(circuit_list, circuit_t *, circ) {
    circuit_count++;
    
    if (CIRCUIT_IS_ORCIRC(circ)) {
      const or_circuit_t *or_circ = CONST_TO_OR_CIRCUIT(circ);
      log_or_circuit_info(conn, or_circ);
    } else if (CIRCUIT_IS_ORIGIN(circ)) {
      const origin_circuit_t *orig_circ = CONST_TO_ORIGIN_CIRCUIT(circ);
      log_origin_circuit_info(conn, orig_circ);
    } else {
      // Unknown circuit type
      control_printf_midreply(conn, 250,
        "UNKNOWN_CIRCUIT "
        "Nickname=%s "
        "N_CircuitID=%u "
        "State=%s "
        "Purpose=%s "
        "MarkedForClose=%s "
        "GlobalListIdx=%d",
        get_options()->Nickname ? get_options()->Nickname : "Unknown",
        circ->n_circ_id,
        circuit_state_to_string_local(circ->state),
        circuit_purpose_to_string_local(circ->purpose),
        circ->marked_for_close ? "true" : "false",
        circ->global_circuitlist_idx);
    }
  } SMARTLIST_FOREACH_END(circ);
  
  control_printf_endreply(conn, 250, "LOGALLCIRCUITS: Enumerated %d circuits for relay %s", circuit_count, nickname);
  
  return 0;
}
