/* Copyright (c) 2024, The ELTOR Project */
/* See LICENSE for licensing information */

/**
 * \file control_teardowncircuit.h
 * \brief Header for TEARDOWNCIRCUIT control command.
 **/

#ifndef TOR_CONTROL_TEARDOWNCIRCUIT_H
#define TOR_CONTROL_TEARDOWNCIRCUIT_H

struct control_connection_t;
struct control_cmd_args_t;
struct control_cmd_syntax_t;
struct circuit_t;

/** Syntax definition for TEARDOWNCIRCUIT command */
extern const struct control_cmd_syntax_t teardowncircuit_syntax;

/** Handle TEARDOWNCIRCUIT control command */
int handle_control_teardowncircuit(struct control_connection_t *conn,
                                   const struct control_cmd_args_t *args);

/** Force immediate circuit destruction for external callers */
void eltor_force_immediate_circuit_destruction(struct circuit_t *circ, int reason);

#endif /* !defined(TOR_CONTROL_TEARDOWNCIRCUIT_H) */
