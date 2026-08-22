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
	MsgRenewRequest  MessageType = "renew_request"  // agent -> gateway, asks for a fresh client cert before the current one expires
	MsgRenewResponse MessageType = "renew_response" // gateway -> agent, the newly signed cert (or an error)
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

// RenewRequest is sent by an agent over its already-established mTLS
// session, asking the gateway to sign a freshly generated key/CSR under the
// same server identity before the agent's current certificate expires.
// Unlike RegisterRequest there is no token: the agent's identity is already
// proven by the client certificate that authenticated this very connection
// (see gateway.go handleConn), so CommonName is taken from that certificate,
// never from anything the agent asserts here.
type RenewRequest struct {
	CSRPEM string `json:"csr_pem"`
}

// RenewResponse carries the newly issued certificate, or Error if the
// gateway declined to renew (e.g. malformed CSR). The agent must not treat
// its old certificate as replaced until it has durably persisted this one.
type RenewResponse struct {
	CertPEM   string    `json:"cert_pem,omitempty"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
	Error     string    `json:"error,omitempty"`
}
