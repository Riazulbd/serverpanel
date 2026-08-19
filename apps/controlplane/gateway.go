package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/riazulbd/serverpanel/packages/proto"
)

// gateway is the mTLS-terminated, agent-facing side of the control plane.
// It is deliberately separate from the public HTTP API (see
// docs/architecture.md §1): only agents holding a certificate signed by our
// internal CA can open a session here, and each session is authenticated by
// the certificate's CommonName (the server_id bound at registration), not
// by anything the agent asserts in-band.
type gateway struct {
	ca    *agentCA
	store *store

	mu       sync.Mutex
	sessions map[string]*agentSession
}

type agentSession struct {
	serverID string
	conn     net.Conn
	enc      *json.Encoder
	mu       sync.Mutex // guards writes to enc and the renewal fields below
	pending  map[string]chan proto.TaskEvent

	// certSerial is the serial of the certificate this session actually
	// authenticated with — the one a completed renewal supersedes.
	certSerial string
	// pendingRenewSerial is set once a successor certificate has been
	// signed and sent but the agent has not yet confirmed it reached disk.
	// Until that confirmation arrives, nothing about the old certificate
	// changes, so an agent that dies mid-renewal reconnects with the
	// certificate it still has rather than being locked out of its own
	// control plane.
	pendingRenewSerial string
	// renewed records that this session already completed one renewal. A
	// session needs at most one; refusing further ones bounds how fast a
	// single misbehaving or compromised agent can churn through serial
	// numbers and revocation-list entries.
	renewed bool
}

func newGateway(ca *agentCA, st *store) *gateway {
	return &gateway{ca: ca, store: st, sessions: map[string]*agentSession{}}
}

// listen binds the mTLS agent listener. It is separate from serve so a
// caller (including a test) can learn the bound address before any agent
// connects — necessary when binding to port 0.
func (g *gateway) listen(addr string) (net.Listener, error) {
	certPEM, keyPEM, err := g.ca.signServerCert([]string{"localhost", "127.0.0.1", "serverpanel-gateway"})
	if err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}

	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    g.ca.certPool(),
		MinVersion:   tls.VersionTLS13,
	}
	return tls.Listen("tcp", addr, cfg)
}

func (g *gateway) serve(ln net.Listener) error {
	log.Printf("agent gateway (mTLS) listening on %s", ln.Addr())
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go g.handleConn(conn)
	}
}

func (g *gateway) listenAndServe(addr string) error {
	ln, err := g.listen(addr)
	if err != nil {
		return err
	}
	return g.serve(ln)
}

func (g *gateway) handleConn(conn net.Conn) {
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		conn.Close()
		return
	}
	if err := tlsConn.Handshake(); err != nil {
		log.Printf("mTLS handshake failed from %s: %v", conn.RemoteAddr(), err)
		conn.Close()
		return
	}

	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		conn.Close()
		return
	}
	clientCert := state.PeerCertificates[0]
	serverID := clientCert.Subject.CommonName
	serial := clientCert.SerialNumber.String()

	if g.store.isRevoked(serial) {
		log.Printf("rejecting connection from revoked cert serial=%s server=%s", serial, serverID)
		conn.Close()
		return
	}
	if _, ok := g.store.get(serverID); !ok {
		log.Printf("rejecting connection: unknown server_id=%s", serverID)
		conn.Close()
		return
	}

	sess := &agentSession{
		serverID:   serverID,
		conn:       conn,
		enc:        json.NewEncoder(conn),
		pending:    map[string]chan proto.TaskEvent{},
		certSerial: serial,
	}

	g.mu.Lock()
	g.sessions[serverID] = sess
	g.mu.Unlock()
	g.store.setConnected(serverID, true)
	g.store.log(serverID, "", "agent.connected", fmt.Sprintf("remote=%s", conn.RemoteAddr()))
	log.Printf("agent connected: server_id=%s remote=%s", serverID, conn.RemoteAddr())

	// Explicit application-level ack: the agent should only report itself
	// "connected" once the gateway has accepted the session (identity known,
	// cert not revoked), not merely once the TLS handshake succeeded.
	sess.mu.Lock()
	err := sess.enc.Encode(proto.Envelope{Type: proto.MsgAck})
	sess.mu.Unlock()
	if err != nil {
		return
	}

	defer func() {
		g.mu.Lock()
		delete(g.sessions, serverID)
		g.mu.Unlock()
		g.store.setConnected(serverID, false)
		g.store.log(serverID, "", "agent.disconnected", "")
		conn.Close()
	}()

	dec := json.NewDecoder(bufio.NewReader(conn))
	for {
		var env proto.Envelope
		if err := dec.Decode(&env); err != nil {
			return
		}
		switch env.Type {
		case proto.MsgHello:
			// Identity is already established from the client cert; Hello
			// is informational (agent version) and logged, not trusted for auth.
			if env.Hello != nil {
				g.store.setAgentVersion(serverID, env.Hello.AgentVersion)
				g.store.log(serverID, "", "agent.hello", fmt.Sprintf("agent_version=%s", env.Hello.AgentVersion))
			}
		case proto.MsgHeartbeat:
			if env.Heartbeat != nil {
				g.store.recordHeartbeat(serverID, heartbeatSnapshot{
					UptimeSecs: env.Heartbeat.UptimeSecs, LoadAvg1: env.Heartbeat.LoadAvg1,
					MemUsedPct: env.Heartbeat.MemUsedPct, DiskUsedPct: env.Heartbeat.DiskUsedPct,
					At: env.Heartbeat.SentAt,
				})
			}
		case proto.MsgRenewRequest:
			if env.RenewRequest != nil {
				g.handleRenewRequest(sess, env.RenewRequest)
			}
		case proto.MsgRenewAck:
			g.handleRenewAck(sess)
		case proto.MsgTaskEvent:
			if env.TaskEvent != nil {
				g.store.log(serverID, "", "task.event", fmt.Sprintf("task_id=%s status=%s message=%q", env.TaskEvent.TaskID, env.TaskEvent.Status, env.TaskEvent.Message))
				sess.mu.Lock()
				ch := sess.pending[env.TaskEvent.TaskID]
				sess.mu.Unlock()
				if ch != nil {
					select {
					case ch <- *env.TaskEvent:
					default:
					}
				}
			}
		}
	}
}

// handleRenewRequest signs a successor to the certificate this session
// authenticated with. The new certificate's identity comes from
// sess.serverID — derived by the gateway from the mTLS handshake, never
// from anything in the request — so an agent cannot renew into a different
// server's identity no matter what it puts in its CSR.
//
// Nothing about the existing certificate changes here. The old serial is
// superseded only once the agent confirms (handleRenewAck) that the new
// certificate is durably on disk; see agentSession.pendingRenewSerial.
func (g *gateway) handleRenewRequest(sess *agentSession, req *proto.RenewRequest) {
	reply := func(resp proto.RenewResponse) {
		sess.mu.Lock()
		defer sess.mu.Unlock()
		_ = sess.enc.Encode(proto.Envelope{Type: proto.MsgRenewResponse, RenewResponse: &resp})
	}

	sess.mu.Lock()
	alreadyRenewed := sess.renewed
	sess.mu.Unlock()
	if alreadyRenewed {
		g.store.log(sess.serverID, "", "agent.cert_renew_refused", "a renewal already completed on this session")
		reply(proto.RenewResponse{Error: "a certificate renewal already completed on this session; reconnect with the new certificate before renewing again"})
		return
	}

	// A revoked agent must not be able to renew its way back into the
	// fleet. Revocation is checked at handshake, but a session can outlive
	// the moment its certificate was revoked, so it is re-checked here —
	// issuing a fresh certificate is exactly the operation where a stale
	// authorization would matter most.
	if g.store.isRevoked(sess.certSerial) {
		g.store.log(sess.serverID, "", "agent.cert_renew_refused", "certificate is revoked")
		reply(proto.RenewResponse{Error: "this certificate has been revoked and cannot be renewed"})
		return
	}

	certPEM, serial, err := g.ca.signAgentCSR([]byte(req.CSRPEM), sess.serverID, agentCertTTL)
	if err != nil {
		g.store.log(sess.serverID, "", "agent.cert_renew_failed", err.Error())
		reply(proto.RenewResponse{Error: "could not sign the renewal request: " + err.Error()})
		return
	}

	sess.mu.Lock()
	sess.pendingRenewSerial = serial.String()
	sess.mu.Unlock()

	g.store.log(sess.serverID, "", "agent.cert_renew_issued",
		fmt.Sprintf("old_serial=%s new_serial=%s awaiting_agent_confirmation=true", sess.certSerial, serial))
	reply(proto.RenewResponse{CertPEM: string(certPEM), CAPEM: string(g.ca.CAPEM())})
}

// handleRenewAck commits a renewal the agent has confirmed it persisted:
// the successor becomes the server's certificate of record and the
// predecessor is revoked, so a copy of the old certificate stolen before
// rotation stops being usable immediately rather than lingering until its
// own expiry.
//
// The live session is deliberately left open even though it authenticated
// with the now-revoked certificate: revocation gates new handshakes, and
// tearing down a healthy connection mid-renewal would turn routine rotation
// into a visible outage. The agent picks up the new certificate on its next
// reconnect.
func (g *gateway) handleRenewAck(sess *agentSession) {
	sess.mu.Lock()
	newSerial := sess.pendingRenewSerial
	oldSerial := sess.certSerial
	if newSerial == "" {
		sess.mu.Unlock()
		return // no renewal outstanding; nothing to commit
	}
	sess.pendingRenewSerial = ""
	sess.renewed = true
	sess.mu.Unlock()

	if err := g.store.commitCertRenewal(sess.serverID, oldSerial, newSerial); err != nil {
		g.store.log(sess.serverID, "", "agent.cert_renew_failed",
			fmt.Sprintf("old_serial=%s new_serial=%s: %v", oldSerial, newSerial, err))
		return
	}
	g.store.log(sess.serverID, "", "agent.cert_renewed",
		fmt.Sprintf("old_serial=%s new_serial=%s", oldSerial, newSerial))
	log.Printf("agent certificate renewed: server_id=%s old_serial=%s new_serial=%s", sess.serverID, oldSerial, newSerial)
}

// dispatch sends a task to a connected agent and waits (bounded by ctx) for
// a terminal TaskEvent. Every call is audit-logged (with the requesting
// user attributed via actor) before the task is sent.
func (g *gateway) dispatch(ctx context.Context, serverID, actor, capability string, params map[string]any) (proto.TaskEvent, error) {
	g.mu.Lock()
	sess, ok := g.sessions[serverID]
	g.mu.Unlock()
	if !ok {
		return proto.TaskEvent{}, fmt.Errorf("server %s is not currently connected", serverID)
	}

	taskID := randID("task")
	task := proto.Task{ID: taskID, Capability: capability, Params: params, IssuedAt: time.Now().UTC()}

	ch := make(chan proto.TaskEvent, 4)
	sess.mu.Lock()
	sess.pending[taskID] = ch
	sess.mu.Unlock()
	defer func() {
		sess.mu.Lock()
		delete(sess.pending, taskID)
		sess.mu.Unlock()
	}()

	g.store.log(serverID, actor, "task.dispatched", fmt.Sprintf("task_id=%s capability=%s", taskID, capability))

	sess.mu.Lock()
	err := sess.enc.Encode(proto.Envelope{Type: proto.MsgTask, Task: &task})
	sess.mu.Unlock()
	if err != nil {
		return proto.TaskEvent{}, fmt.Errorf("send task: %w", err)
	}

	for {
		select {
		case ev := <-ch:
			if ev.Status == proto.TaskSucceeded || ev.Status == proto.TaskFailed || ev.Status == proto.TaskRejected {
				return ev, nil
			}
		case <-ctx.Done():
			return proto.TaskEvent{}, ctx.Err()
		}
	}
}

// forceDisconnect closes a live session, used immediately on revocation so
// a revoked agent cannot keep using an already-open connection.
func (g *gateway) forceDisconnect(serverID string) {
	g.mu.Lock()
	sess, ok := g.sessions[serverID]
	g.mu.Unlock()
	if ok {
		sess.conn.Close()
	}
}
