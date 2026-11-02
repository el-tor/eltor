/* Copyright (c) 2026, The El Tor Project. */
/* See LICENSE for licensing information. */
#ifndef TOR_FREE_CAPACITY_HOOKS_H
#define TOR_FREE_CAPACITY_HOOKS_H
#include "core/or/or.h"
#include "feature/payment/free_capacity.h"
struct free_capacity_context_t;
struct free_capacity_link_t;
/* Explicit main-loop provisional admission before expensive handshake work.
 * Only the frozen eligibility flag may enter the worker. Confirm only after
 * exact authenticated resource-profile negotiation; keys/dummy proofs and
 * TestingTorNetwork never manufacture admission. Retain provisional state
 * through actual worker completion; no enabled descriptor is provided here. */
int free_capacity_circuit_prepare(circuit_t *, or_connection_t *);
int free_capacity_circuit_prepare_channel(circuit_t *, channel_t *);
/* Relay-only: account the original received CREATE that preceded provisional
 * circuit allocation. Existing enabled-link byte debit is not repeated. */
int free_capacity_circuit_setup_received(circuit_t *, channel_t *);
int free_capacity_circuit_confirm(circuit_t *);
/* Nonnegotiated one-hop directory bootstrap is an immutable local restriction,
 * never authenticated normal admission or paid authority. All existing limits
 * remain in force; recognized commands must pass the directory-only gate. */
int free_capacity_circuit_confirm_bootstrap(circuit_t *);
bool free_capacity_circuit_is_bootstrap(const circuit_t *);
bool free_capacity_circuit_is_normal(const circuit_t *);
bool free_capacity_bootstrap_command_allowed(const circuit_t *, uint8_t command,
    uint16_t stream_id, bool established_directory_stream);
int free_capacity_circuit_admit(circuit_t *, or_connection_t *);
void free_capacity_circuit_free(circuit_t *);
/* Read-only admission/lifetime gate. Does not refill buckets or grant paid
 * authority; all-hop authenticated ACK checks remain with the origin. */
bool free_capacity_circuit_ready(const circuit_t *, uint64_t now_ms);
/* Irreversible transition after independently verified paid activation. Keeps
 * original counters/old queue receipts; never grants a later free fallback. */
void free_capacity_circuit_paid(circuit_t *);
bool free_capacity_circuit_is_paid(const circuit_t *);
void free_capacity_connection_free(or_connection_t *);
/* Central serialized link hooks. Return false only after closing the affected
 * circuit/connection. Stateful incoming cells must never be skipped and then
 * resumed. Padding and variable maintenance count once on enabled links. */
bool free_capacity_wire_receive(or_connection_t *, circid_t, uint32_t bytes,
                                bool fixed, uint8_t command);
bool free_capacity_wire_send(or_connection_t *, circid_t, uint32_t bytes,
                             bool fixed, uint8_t command);
/* Reserve before packed-cell allocation. Release on actual cell destruction or
 * transfer out of the bounded circuit queues. Both directions share 32 cells. */
int free_capacity_cell_reserve(circuit_t *, free_capacity_queue_ticket_t *);
/* Provisional contexts admit only fixed setup commands to the same bounded
 * queues. Ordinary RELAY/control traffic still requires confirmation. */
int free_capacity_cell_reserve_command(circuit_t *,
    free_capacity_queue_ticket_t *, uint8_t cell_command);
void free_capacity_cell_release(circuit_t *, free_capacity_queue_ticket_t *);
/* Pre-pop send gate: OK sends once; WAIT suppresses only this circuit's cmux
 * queues until a finite timer wakes them; CLOSE tears down the circuit. */
free_capacity_result_t free_capacity_circuit_send(circuit_t *, channel_t *);
free_capacity_result_t free_capacity_circuit_send_control(circuit_t *,
    channel_t *, bool locally_generated_payment_control);
free_capacity_result_t free_capacity_circuit_send_cell(circuit_t *,
    channel_t *, bool locally_generated_payment_control, uint8_t cell_command);
void free_capacity_circuit_queued(circuit_t *);
MOCK_DECL(bool, free_capacity_paid_data_active, (const circuit_t *));
#endif
