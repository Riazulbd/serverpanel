package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/riazulbd/serverpanel/packages/proto"
)

// agentCertTTL is the lifetime granted to an agent's client certificate,
// both at initial registration (http.go handleRegister) and at every
// subsequent renewal (handleRenewRequest below) — a routine like-for-like
// rotation always gets the same short TTL, never an escalation.
const agentCertTTL = 30 * 24 * time.Hour

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
	mu       sync.Mutex // guards writes to enc and pendingRenewalOldSerial
	pending  map[string]chan proto.TaskEvent

	// pendingRenewalOldSerial is set to the serial of the certificate that
	// authenticated this connection when a renewal has been issued but not
	// yet confirmed applied by the agent (see handleRenewRequest and the
	// MsgRenewConfirm case in handleConn). Empty when no renewal is
	// in-flight. The old certificate is only added to the revocation list
	// once the agent confirms it has switched to the new one — see
	// handleRenewRequest's doc comment for why.
	pendingRenewalOldSerial string
}

func newGateway(ca *agentCA, st *store) *gateway {
	return &gateway{ca: ca, store: st, sessions: map[string]*agentSession{}}
}

func (g *gateway) listenAndServe(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return g.serve(ln)
}

// serve runs the mTLS accept loop over an already-bound listener. Split out
// from listenAndServe so tests can bind an ephemeral port (net.Listen with
// ":0") and read back the actual address before serving on it, instead of
// guessing/reserving a fixed port.
func (g *gateway) serve(ln net.Listener) error {
	certPEM, keyPEM, err := g.ca.signServerCert([]string{"localhost", "127.0.0.1", "serverpanel-gateway"})
	if err != nil {
		return err
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return err
	}

	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    g.ca.certPool(),
		MinVersion:   tls.VersionTLS13,
	}

	ln = tls.NewListener(ln, cfg)
	log.Printf("agent gateway (mTLS) listening on %s", ln.Addr())

	for {
		conn, err := ln.Accept()
		if err != nil {
			// A closed listener (normal shutdown, or a test tearing down)
			// makes every subsequent Accept fail permanently — looping on
			// `continue` here would busy-spin forever, burning CPU and
			// flooding the log rather than actually stopping. Returning is
			// the correct terminal behavior for that case; any other
			// (transient) accept error gets a short backoff instead of a
			// tight retry loop.
			if errors.Is(err, net.ErrClosed) {
				return err
			}
			log.Printf("gateway accept error: %v", err)
			time.Sleep(100 * time.Millisecond)
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
				g.handleRenewRequest(sess, serverID, serial, *env.RenewRequest)
			}
		case proto.MsgRenewConfirm:
			g.handleRenewConfirm(sess, serverID)
		}
	}
}

// handleRenewRequest issues a fresh client certificate to an agent that is
// approaching its current certificate's expiry. serverID and oldSerial come
// from the already-verified client certificate on this live mTLS session
// (see handleConn above) — never from the CSR's requested subject or any
// other caller-supplied value — so a session cannot renew into an identity
// other than the one it authenticated as, and the gateway (not the agent)
// decides which serial renewal is replacing.
//
// The certificate this replaces is deliberately NOT revoked here. Revoking
// it immediately would risk permanently locking the agent out if this
// RenewResponse never arrives or the agent fails to persist it (disk full,
// process killed mid-write, ...): the agent would keep retrying with a
// certificate the gateway has already rejected, with no path back except
// manual re-registration. Instead oldSerial is stashed on the session and
// only actually revoked once the agent explicitly confirms (MsgRenewConfirm,
// see handleRenewConfirm) that it has switched over — see connect.go's
// renewal flow. Until then, both certificates remain valid, which is a
// deliberately safe trade against a self-inflicted disconnect: the short TTL
// (agentCertTTL) already bounds how long that overlap can matter.
func (g *gateway) handleRenewRequest(sess *agentSession, serverID, oldSerial string, req proto.RenewRequest) {
	certPEM, serial, err := g.ca.signAgentCSR([]byte(req.CSRPEM), serverID, agentCertTTL)
	if err != nil {
		g.store.log(serverID, "", "agent.cert_renewal_failed", err.Error())
		return
	}

	expiresAt := time.Now().Add(agentCertTTL)
	if leaf, perr := x509.ParseCertificate(mustDecodeSingleCertDER(certPEM)); perr == nil {
		expiresAt = leaf.NotAfter
	}

	g.store.renewCert(serverID, serial.String())

	sess.mu.Lock()
	sess.pendingRenewalOldSerial = oldSerial
	err = sess.enc.Encode(proto.Envelope{Type: proto.MsgRenewResponse, RenewResponse: &proto.RenewResponse{
		CertPEM: string(certPEM), ExpiresAt: expiresAt,
	}})
	sess.mu.Unlock()
	if err != nil {
		log.Printf("failed to send renewed certificate to server_id=%s: %v", serverID, err)
	}
}

// handleRenewConfirm revokes the certificate a renewal replaced, now that
// the agent has confirmed (by persisting the new cert/key to disk and
// sending MsgRenewConfirm) that it no longer depends on the old one. A
// confirm with nothing pending (already handled, or a stray duplicate) is a
// harmless no-op.
func (g *gateway) handleRenewConfirm(sess *agentSession, serverID string) {
	sess.mu.Lock()
	oldSerial := sess.pendingRenewalOldSerial
	sess.pendingRenewalOldSerial = ""
	sess.mu.Unlock()
	if oldSerial == "" {
		return
	}
	g.store.revokeCertSerial(serverID, oldSerial)
}

// mustDecodeSingleCertDER extracts the DER bytes of a single PEM-encoded
// certificate for re-parsing its real NotAfter. Only used for the
// informational ExpiresAt field in RenewResponse — if this ever fails to
// parse (it never should, since signAgentCSR just produced it), the caller
// falls back to a computed expiry, so this deliberately swallows the error
// via a zero-value return.
func mustDecodeSingleCertDER(certPEM []byte) []byte {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil
	}
	return block.Bytes
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
