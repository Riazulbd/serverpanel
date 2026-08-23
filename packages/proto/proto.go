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
	MsgRenewCSR  MessageType = "renew_csr"  // agent -> gateway, requests a fresh client cert over the already-authenticated session
	MsgRenewCert MessageType = "renew_cert" // gateway -> agent, terminal reply to a renew_csr (new cert, or an error)
)

// Envelope is the outer message wrapper. Exactly one of the typed payload
// fields is populated, matching Type.
type Envelope struct {
	Type      MessageType `json:"type"`
	Hello     *Hello      `json:"hello,omitempty"`
	Heartbeat *Heartbeat  `json:"heartbeat,omitempty"`
	Task      *Task       `json:"task,omitempty"`
	TaskEvent *TaskEvent  `json:"task_event,omitempty"`
	RenewCSR  *RenewCSR   `json:"renew_csr,omitempty"`
	RenewCert *RenewCert  `json:"renew_cert,omitempty"`
}

// RenewCSR is sent by the agent, over its existing mTLS session, when its
// current client certificate is approaching expiry. It carries no
// credential of its own — trust for the renewal comes entirely from the
// fact that this message arrives on a connection the gateway already
// authenticated via the agent's *current, still-valid* certificate (see
// gateway.handleConn), matching the documented rotation model in
// docs/SECURITY.md §2. There is deliberately no separate renewal HTTP
// endpoint: the mTLS session itself is the credential.
type RenewCSR struct {
	CSRPEM string `json:"csr_pem"`
}

// RenewCert is the terminal reply to a RenewCSR: either a freshly issued
// certificate for the same server identity, or an error the agent should
// log and retry later (its current certificate remains valid and the
// connection stays up either way).
type RenewCert struct {
	CertPEM  string    `json:"cert_pem,omitempty"`
	NotAfter time.Time `json:"not_after,omitempty"`
	Error    string    `json:"error,omitempty"`
}

// AgentCertTTL is the validity period of an agent client certificate,
// applied identically at initial registration (apiServer.handleRegister)
// and at every subsequent renewal (gateway.handleRenewCSR) — renewal
// issues a same-length certificate, it does not extend validity further
// into the future than a fresh registration would.
const AgentCertTTL = 30 * 24 * time.Hour

// AgentCertRenewalWindow is how long before expiry an agent proactively
// requests a renewed certificate (see docs/SECURITY.md §2). It must leave
// enough margin that a control plane or network outage lasting several
// days doesn't turn into a missed renewal and a forced manual
// re-registration.
const AgentCertRenewalWindow = 10 * 24 * time.Hour

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
