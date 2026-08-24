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
	MsgHello     MessageType = "hello"      // agent -> gateway, first message after mTLS connect
	MsgHeartbeat MessageType = "heartbeat"  // agent -> gateway, periodic health snapshot
	MsgTask      MessageType = "task"       // gateway -> agent, requests a capability run
	MsgTaskEvent MessageType = "task_event" // agent -> gateway, progress/result of a task
	MsgAck       MessageType = "ack"        // either direction, generic acknowledgement

	// Certificate renewal. Deliberately carried over the already-established
	// mTLS session rather than a second HTTP endpoint: the agent's identity
	// is then derived from the certificate it is currently authenticated
	// with, so renewal needs no bootstrap token, no new unauthenticated
	// surface, and cannot be used to obtain a certificate for a different
	// server.
	MsgCertRenewRequest  MessageType = "cert_renew_request"  // agent -> gateway
	MsgCertRenewResponse MessageType = "cert_renew_response" // gateway -> agent
)

// Envelope is the outer message wrapper. Exactly one of the typed payload
// fields is populated, matching Type.
type Envelope struct {
	Type              MessageType        `json:"type"`
	Hello             *Hello             `json:"hello,omitempty"`
	Heartbeat         *Heartbeat         `json:"heartbeat,omitempty"`
	Task              *Task              `json:"task,omitempty"`
	TaskEvent         *TaskEvent         `json:"task_event,omitempty"`
	CertRenewRequest  *CertRenewRequest  `json:"cert_renew_request,omitempty"`
	CertRenewResponse *CertRenewResponse `json:"cert_renew_response,omitempty"`
}

// CertRenewRequest asks the gateway to sign a fresh client certificate for
// the agent. It carries only a CSR: the server identity the certificate is
// issued for comes from the mTLS peer certificate of the connection the
// request arrives on, never from anything in this message, so an agent can
// only ever renew its own identity.
type CertRenewRequest struct {
	CSRPEM string `json:"csr_pem"`
}

// CertRenewResponse returns the newly signed certificate, or Error
// explaining why renewal was refused. CAPEM is echoed back so an agent also
// picks up a rotated CA root without a re-registration.
type CertRenewResponse struct {
	CertPEM  string    `json:"cert_pem,omitempty"`
	CAPEM    string    `json:"ca_pem,omitempty"`
	Serial   string    `json:"serial,omitempty"`
	NotAfter time.Time `json:"not_after,omitempty"`
	Error    string    `json:"error,omitempty"`
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
