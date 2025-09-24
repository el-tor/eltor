/**
 * \file control_logallcircuits.h
 * \brief Header for LOGALLCIRCUITS control command.
 **/

#ifndef TOR_CONTROL_LOGALLCIRCUITS_H
#define TOR_CONTROL_LOGALLCIRCUITS_H

struct control_connection_t;
struct control_cmd_args_t;
struct control_cmd_syntax_t;

/** Syntax object for the LOGALLCIRCUITS command. */
extern const struct control_cmd_syntax_t logallcircuits_syntax;

/** Implementation for the LOGALLCIRCUITS command. */
int handle_control_logallcircuits(struct control_connection_t *conn,
                                  const struct control_cmd_args_t *args);

#endif /* !defined(TOR_CONTROL_LOGALLCIRCUITS_H) */
