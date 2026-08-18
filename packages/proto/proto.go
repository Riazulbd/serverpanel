// Package proto defines the wire types shared between the control plane's
// agent gateway and the server agent. The protocol is intentionally small:
// the control plane may only ask an agent to run one of a fixed set of named
// Capabilities (see Capability* constants) with a JSON parameter object. There
// is no "run this shell command" message type in this protocol, by design —
// see docs/security-trust-model.md.
package proto

import "time"

// MessageType identifies the kind of Envelope being sent over the
// newline-delimited JSON connection between an agent and the gateway.
type MessageType string

const (
	MsgHello         MessageType = "hello"          // agent -> gateway, first message after mTLS connect
	MsgHeartbeat     MessageType = "heartbeat"      // agent -> gateway, periodic health snapshot
	MsgTask          MessageType = "task"           // gateway -> agent, requests a capability run
	MsgTaskEvent     MessageType = "task_event"     // agent -> gateway, progress/result of a task
	MsgAck           MessageType = "ack"            // either direction, generic acknowledgement
	MsgRenewRequest  MessageType = "renew_request"  // agent -> gateway, requests a fresh client cert before the current one expires
	MsgRenewResponse MessageType = "renew_response" // gateway -> agent, carries the newly issued cert (or a rejection reason)
)

// Envelope is the outer message wrapper. Exactly one of the typed payload
// fields is populated, matching Type.
type Envelope struct {
	Type          MessageType    `json:"type"`
	Hello         *Hello         `json:"hello,omitempty"`
	Heartbeat     *Heartbeat     `json:"heartbeat,omitempty"`
	Task          *Task          `json:"task,omitempty"`
	TaskEvent     *TaskEvent     `json:"task_event,omitempty"`
	RenewRequest  *RenewRequest  `json:"renew_request,omitempty"`
	RenewResponse *RenewResponse `json:"renew_response,omitempty"`
}

// Hello is sent by the agent immediately after the mTLS handshake completes,
// confirming which server identity it believes it is (the gateway also
// derives this independently from the client certificate's CommonName and
// rejects a mismatch).
type Hello struct {
	ServerID     string `json:"server_id"`
	AgentVersion string `json:"agent_version"`
}

// Heartbeat is a lightweight, periodic health snapshot. It intentionally
// carries only aggregated numbers, never raw logs.
type Heartbeat struct {
	SentAt      time.Time `json:"sent_at"`
	UptimeSecs  int64     `json:"uptime_secs"`
	LoadAvg1    float64   `json:"load_avg_1"`
	MemUsedPct  float64   `json:"mem_used_pct"`
	DiskUsedPct float64   `json:"disk_used_pct"`
}

// TaskStatus is the lifecycle state of a dispatched Task.
type TaskStatus string

const (
	TaskQueued    TaskStatus = "queued"
	TaskRunning   TaskStatus = "running"
	TaskSucceeded TaskStatus = "succeeded"
	TaskFailed    TaskStatus = "failed"
	TaskRejected  TaskStatus = "rejected" // capability unknown/params invalid: agent refuses without running anything
)

// Task is a single unit of work the control plane asks an agent to perform.
// Capability must be one of the names registered in
// packages/capabilities, and Params is validated by that capability's
// handler before anything is executed — an unrecognized Capability is
// rejected by the agent, never attempted.
type Task struct {
	ID         string         `json:"id"`
	Capability string         `json:"capability"`
	Params     map[string]any `json:"params"`
	IssuedAt   time.Time      `json:"issued_at"`
}

// TaskEvent reports progress or a terminal result for a Task. An agent may
// send multiple TaskEvents for one task_id (e.g. "running" then
// "succeeded"); the final event has a terminal Status.
type TaskEvent struct {
	TaskID  string     `json:"task_id"`
	Status  TaskStatus `json:"status"`
	Message string     `json:"message,omitempty"`
	Detail  string     `json:"detail,omitempty"`
	At      time.Time  `json:"at"`
}

// RenewRequest is sent by an already-connected agent, over its existing
// mTLS session, to obtain a fresh client certificate before its current one
// expires. No bootstrap token is involved: the request is implicitly
// authenticated by the mTLS session it arrives on, which the gateway has
// already bound to a server_id via the peer certificate's CommonName (see
// gateway.handleConn) — CSRPEM is only ever used to bind a *new* keypair to
// that same, already-established identity, never to claim a different one.
type RenewRequest struct {
	CSRPEM string `json:"csr_pem"`
}

// RenewResponse carries the newly issued certificate, or a non-empty Error
// if the gateway declined to renew (e.g. the server record no longer
// exists). A declined renewal does not close the current session — the
// agent keeps operating on its existing (still valid) certificate and
// retries renewal on a later cycle.
type RenewResponse struct {
	CertPEM string `json:"cert_pem,omitempty"`
	Error   string `json:"error,omitempty"`
}

// RegisterRequest is the body of the one-time POST /agents/register call
// made over plain server-TLS (the agent has no client certificate yet — that
// is what this call obtains). Token is the single-use bootstrap secret
// printed by the install command.
type RegisterRequest struct {
	Token  string `json:"token"`
	CSRPEM string `json:"csr_pem"`
}

// RegisterResponse hands back a durable machine identity: a short-lived
// client certificate bound to ServerID, plus the CA the agent should pin for
// verifying the gateway's own TLS certificate.
type RegisterResponse struct {
	ServerID    string `json:"server_id"`
	CertPEM     string `json:"cert_pem"`
	CAPEM       string `json:"ca_pem"`
	GatewayAddr string `json:"gateway_addr"`
}
