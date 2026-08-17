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
)

// Envelope is the outer message wrapper. Exactly one of the typed payload
// fields is populated, matching Type.
type Envelope struct {
	Type      MessageType `json:"type"`
	Hello     *Hello      `json:"hello,omitempty"`
	Heartbeat *Heartbeat  `json:"heartbeat,omitempty"`
	Task      *Task       `json:"task,omitempty"`
	TaskEvent *TaskEvent  `json:"task_event,omitempty"`
}

// Hello is sent by the agent immediately after the mTLS handshake completes,
// confirming which server identity it believes it is (the gateway also
// derives this independently from the client certificate's CommonName and
// rejects a mismatch). It also carries facts about the host that change
// rarely if ever during a connection's lifetime (IP, CPU count, total
// memory/disk) — sent once here rather than repeated on every Heartbeat,
// keeping steady-state heartbeat traffic to just the numbers that actually
// change (docs/SYSTEM.md §22 performance decisions).
type Hello struct {
	ServerID     string  `json:"server_id"`
	AgentVersion string  `json:"agent_version"`
	PublicIP     string  `json:"public_ip,omitempty"`
	CPUCores     int     `json:"cpu_cores,omitempty"`
	MemTotalMB   float64 `json:"mem_total_mb,omitempty"`
	DiskTotalMB  float64 `json:"disk_total_mb,omitempty"`
}

// Heartbeat is a lightweight, periodic health snapshot. It intentionally
// carries only aggregated numbers, never raw logs. The *UsedPct fields are
// kept (rather than replaced) alongside the newer absolute-value fields
// because the dashboard's gauges only need a percentage — deriving it
// client-side from used/total would just be re-doing division the agent
// already did once.
type Heartbeat struct {
	SentAt      time.Time `json:"sent_at"`
	UptimeSecs  int64     `json:"uptime_secs"`
	LoadAvg1    float64   `json:"load_avg_1"`
	MemUsedPct  float64   `json:"mem_used_pct"`
	DiskUsedPct float64   `json:"disk_used_pct"`
	MemUsedMB   float64   `json:"mem_used_mb,omitempty"`
	DiskUsedMB  float64   `json:"disk_used_mb,omitempty"`
	SwapTotalMB float64   `json:"swap_total_mb,omitempty"`
	SwapUsedMB  float64   `json:"swap_used_mb,omitempty"`
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
