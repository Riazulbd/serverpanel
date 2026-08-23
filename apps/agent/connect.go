package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/riazulbd/serverpanel/packages/capabilities"
	"github.com/riazulbd/serverpanel/packages/proto"
)

const agentVersion = "0.1.0-dev"

// certRenewalWindow mirrors the control plane's agentCertTTL (30 days,
// apps/controlplane/ca.go) minus a week of slack: the agent starts asking
// for a fresh certificate once less than this much of its current one's
// lifetime remains, so a transient network/control-plane outage still
// leaves several retry opportunities before the old cert actually expires
// and the agent would otherwise have to fall back to manual re-registration
// (docs/SECURITY.md §2).
const certRenewalWindow = 7 * 24 * time.Hour

// certRenewalCheckInterval is how often the connection checks whether its
// current certificate has entered the renewal window. Cheap (just parses
// the already-in-memory cert), so a modest interval is fine — this is not a
// network call.
const certRenewalCheckInterval = time.Hour

// envelopeSender serializes writes to the shared connection encoder.
// Heartbeats, task results, and certificate-renewal requests are all sent
// from independent goroutines on the same underlying net.Conn; without a
// lock, two concurrent json.Encoder.Encode calls could interleave their
// writes mid-message and corrupt the wire protocol for both.
type envelopeSender struct {
	mu  sync.Mutex
	enc *json.Encoder
}

func (s *envelopeSender) send(env proto.Envelope) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.enc.Encode(env)
}

// runConnection maintains one mTLS session to the gateway: sends Hello,
// then loops sending periodic heartbeats and executing any Task the
// gateway sends, replying with TaskEvents. The hosted services the agent
// manages (nginx, php-fpm, mariadb, ...) run under systemd independent of
// this connection — see docs/architecture.md §2 — so a dropped connection
// here degrades orchestration/observability only, never site serving.
func runConnection(ctx context.Context, id *identity, dataDir string, reg capabilities.Registry) error {
	cert, err := tls.X509KeyPair(id.CertPEM, id.KeyPEM)
	if err != nil {
		return err
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(id.CAPEM) {
		log.Fatal("could not parse pinned CA certificate")
	}

	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caPool,
		MinVersion:   tls.VersionTLS13,
	}

	dialer := &net.Dialer{Timeout: 15 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", id.GatewayAddr, cfg)
	if err != nil {
		return err
	}

	sender := &envelopeSender{enc: json.NewEncoder(conn)}
	dec := json.NewDecoder(bufio.NewReader(conn))

	if err := sender.send(proto.Envelope{Type: proto.MsgHello, Hello: &proto.Hello{ServerID: id.ServerID, AgentVersion: agentVersion}}); err != nil {
		return err
	}

	// Wait for the gateway's application-level ack before declaring the
	// session established: a successful TLS handshake alone doesn't mean
	// the gateway accepted the session (e.g. a revoked-but-not-yet-expired
	// certificate still completes a handshake but gets closed immediately
	// after — see apps/controlplane/gateway.go handleConn).
	var ack proto.Envelope
	if err := dec.Decode(&ack); err != nil {
		return fmt.Errorf("did not receive session ack from gateway: %w", err)
	}
	if ack.Type != proto.MsgAck {
		return fmt.Errorf("expected ack from gateway, got %q", ack.Type)
	}
	log.Printf("connected to gateway %s as %s", id.GatewayAddr, id.ServerID)

	renewResultCh := make(chan proto.RenewResponse, 1)
	connCtx, cancelConn := context.WithCancel(ctx)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); heartbeatLoop(connCtx, sender) }()
	go func() { defer wg.Done(); renewalLoop(connCtx, sender, renewResultCh, id, dataDir) }()

	// cancelConn stops both background loops; wg.Wait blocks until they've
	// actually exited before this function returns, so main.go's reconnect
	// loop can never read/dial with id.CertPEM/id.KeyPEM while renewOnce is
	// still mutating them on another goroutine — that race is closed here
	// rather than by locking every field access, since the mutation only
	// ever needs to be safe *across* connection attempts, never within one.
	defer func() {
		cancelConn()
		wg.Wait()
		conn.Close()
	}()

	for {
		var env proto.Envelope
		if err := dec.Decode(&env); err != nil {
			return err
		}
		switch env.Type {
		case proto.MsgTask:
			if env.Task != nil {
				go handleTask(ctx, sender, reg, *env.Task)
			}
		case proto.MsgRenewResponse:
			if env.RenewResponse != nil {
				select {
				case renewResultCh <- *env.RenewResponse:
				default:
					// A stale/duplicate response with no reader waiting;
					// dropping it is safe since renewalLoop only ever
					// expects one outstanding request at a time.
				}
			}
		}
	}
}

func handleTask(ctx context.Context, sender *envelopeSender, reg capabilities.Registry, task proto.Task) {
	send := func(ev proto.TaskEvent) {
		ev.TaskID = task.ID
		ev.At = time.Now().UTC()
		_ = sender.send(proto.Envelope{Type: proto.MsgTaskEvent, TaskEvent: &ev})
	}

	send(proto.TaskEvent{Status: proto.TaskRunning, Message: "starting " + task.Capability})

	// Stack installs and app deployments (apt installs, WordPress core
	// download, ...) can legitimately take minutes over a slow VPS network
	// link; a short timeout here would abort a perfectly healthy install.
	taskCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	progress := func(message string) {
		send(proto.TaskEvent{Status: proto.TaskRunning, Message: message})
	}

	detail, err := reg.Dispatch(taskCtx, task.Capability, task.Params, progress)
	if err != nil {
		send(proto.TaskEvent{Status: proto.TaskFailed, Message: err.Error()})
		return
	}
	send(proto.TaskEvent{Status: proto.TaskSucceeded, Message: "ok", Detail: detail})
}

func heartbeatLoop(ctx context.Context, sender *envelopeSender) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			hb := proto.Heartbeat{
				SentAt:      time.Now().UTC(),
				UptimeSecs:  uptimeSecs(),
				LoadAvg1:    loadAvg1(),
				MemUsedPct:  memUsedPct(),
				DiskUsedPct: diskUsedPct(),
			}
			_ = sender.send(proto.Envelope{Type: proto.MsgHeartbeat, Heartbeat: &hb})
		}
	}
}

// certExpiry parses the NotAfter time of a PEM-encoded client certificate.
func certExpiry(certPEM []byte) (time.Time, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return time.Time{}, fmt.Errorf("invalid certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, err
	}
	return cert.NotAfter, nil
}

// needsRenewal reports whether a certificate expiring at notAfter should be
// renewed now, given the current time. Pulled out as a pure function so the
// renewal threshold is unit-testable without any TLS/network setup.
func needsRenewal(notAfter, now time.Time) bool {
	return notAfter.Sub(now) < certRenewalWindow
}

// renewalLoop periodically checks whether the certificate this connection
// is currently using is close enough to expiry to renew (see
// certRenewalWindow), and if so, requests a fresh one over this same
// already-authenticated mTLS session — no bootstrap token needed, matching
// docs/SECURITY.md §2's "renewal authenticated by its current still-valid
// cert" design. A successful renewal is persisted to disk and applied to
// the in-memory identity in place, so the *next* reconnect (this
// connection itself keeps running on its already-established TLS session
// until it naturally drops) picks up the new certificate automatically —
// see main.go's reconnect loop, which reuses the same *identity across
// calls to runConnection.
func renewalLoop(ctx context.Context, sender *envelopeSender, resultCh <-chan proto.RenewResponse, id *identity, dataDir string) {
	ticker := time.NewTicker(certRenewalCheckInterval)
	defer ticker.Stop()

	// Check once shortly after connecting (covers the case where the agent
	// was offline across its entire renewal window and reconnects with a
	// cert that's already due) and then on the regular interval.
	renewOnce(ctx, sender, resultCh, id, dataDir)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			renewOnce(ctx, sender, resultCh, id, dataDir)
		}
	}
}

func renewOnce(ctx context.Context, sender *envelopeSender, resultCh <-chan proto.RenewResponse, id *identity, dataDir string) {
	expiry, err := certExpiry(id.CertPEM)
	if err != nil {
		log.Printf("cert renewal: could not parse current certificate, skipping check: %v", err)
		return
	}
	if !needsRenewal(expiry, time.Now()) {
		return
	}
	log.Printf("certificate expires %s, requesting renewal", expiry.Format(time.RFC3339))

	key, csrPEM, err := generateKeyAndCSR(id.ServerID)
	if err != nil {
		log.Printf("cert renewal: generate CSR: %v", err)
		return
	}
	if err := sender.send(proto.Envelope{Type: proto.MsgRenewRequest, RenewRequest: &proto.RenewRequest{CSRPEM: string(csrPEM)}}); err != nil {
		log.Printf("cert renewal: send request: %v", err)
		return
	}

	select {
	case resp := <-resultCh:
		if resp.Error != "" {
			log.Printf("cert renewal refused by control plane: %s", resp.Error)
			return
		}
		keyDER, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			log.Printf("cert renewal: marshal new key: %v", err)
			return
		}
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
		if err := writeIdentityFiles(dataDir, []byte(resp.CertPEM), keyPEM); err != nil {
			log.Printf("cert renewal: persist new identity: %v", err)
			return
		}
		id.CertPEM = []byte(resp.CertPEM)
		id.KeyPEM = keyPEM
		log.Printf("certificate renewed; will be used on next reconnect")
	case <-time.After(30 * time.Second):
		log.Printf("cert renewal: timed out waiting for control plane response")
	case <-ctx.Done():
	}
}

func uptimeSecs() int64 {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return 0
	}
	secs, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0
	}
	return int64(secs)
}
