package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
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
	mu       sync.Mutex // guards writes to enc
	pending  map[string]chan proto.TaskEvent
}

func newGateway(ca *agentCA, st *store) *gateway {
	return &gateway{ca: ca, store: st, sessions: map[string]*agentSession{}}
}

func (g *gateway) listenAndServe(addr string) error {
	ln, err := g.newTLSListener(addr)
	if err != nil {
		return err
	}
	log.Printf("agent gateway (mTLS) listening on %s", addr)
	return g.serve(ln)
}

// newTLSListener builds the mTLS listener without starting the accept loop,
// so tests can bind an ephemeral port (addr "127.0.0.1:0"), read back the
// real address from the returned net.Listener, and drive serve in a
// goroutine — exercising the real wire protocol instead of mocking it.
func (g *gateway) newTLSListener(addr string) (net.Listener, error) {
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

// serve runs the accept loop. It returns cleanly (nil) once ln is closed,
// rather than spinning in a tight error-log loop forever — the original
// version of this loop kept calling Accept and logging after the listener
// was closed, which would busy-loop pinning a CPU core with no way to stop
// it short of killing the process.
func (g *gateway) serve(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			log.Printf("gateway accept error: %v", err)
			continue
		}
		go g.handleConn(conn)
	}
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
		serverID: serverID,
		conn:     conn,
		enc:      json.NewEncoder(conn),
		pending:  map[string]chan proto.TaskEvent{},
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
		case proto.MsgRenewRequest:
			if env.RenewRequest != nil {
				g.handleRenew(sess, serverID, *env.RenewRequest)
			}
		}
	}
}

// handleRenew issues a fresh client certificate to replace the one the
// requesting agent is about to outgrow, so a healthy agent never has to
// wait for its certificate to actually expire (and become unable to
// reconnect at all) before rotating. serverID comes from the already
// -verified peer certificate on this connection (see handleConn above),
// never from the CSR itself, for the same reason handleRegister ignores
// the CSR's requested subject: identity is established by the channel, not
// asserted in-band.
func (g *gateway) handleRenew(sess *agentSession, serverID string, req proto.RenewRequest) {
	certPEM, serial, notAfter, err := g.ca.signAgentCSR([]byte(req.CSRPEM), serverID, agentCertTTL)
	if err != nil {
		g.store.log(serverID, "", "agent.cert_renewal_failed", err.Error())
		log.Printf("cert renewal failed for server_id=%s: %v", serverID, err)
		return
	}
	g.store.renewCert(serverID, serial.String(), notAfter)

	sess.mu.Lock()
	err = sess.enc.Encode(proto.Envelope{Type: proto.MsgRenewResponse, RenewResponse: &proto.RenewResponse{CertPEM: string(certPEM)}})
	sess.mu.Unlock()
	if err != nil {
		log.Printf("failed to send renewed certificate to server_id=%s: %v", serverID, err)
	}
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
