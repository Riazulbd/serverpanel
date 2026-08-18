package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
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

// renewalCheckInterval is how often the agent checks whether its current
// client certificate is close enough to expiry to renew. renewalThreshold is
// how much validity must remain before a check triggers an actual renewal
// request — see docs/SECURITY.md §2. Against the 30-day TTL the control
// plane issues (apps/controlplane/gateway.go agentCertTTL), a 7-day
// threshold leaves multiple hourly check cycles to retry before expiry even
// if the first few attempts fail (e.g. transient disconnect).
const (
	renewalCheckInterval = time.Hour
	renewalThreshold     = 7 * 24 * time.Hour
)

// safeEncoder serializes writes to the shared connection encoder.
// heartbeatLoop, handleTask (one goroutine per in-flight task), and
// renewalLoop all encode Envelopes onto the same net.Conn concurrently;
// json.Encoder itself has no internal locking, so without this a
// heartbeat and a task result racing to Encode() at the same instant could
// interleave their writes into a single corrupted line on the wire.
type safeEncoder struct {
	mu  sync.Mutex
	enc *json.Encoder
}

func (s *safeEncoder) Encode(env proto.Envelope) error {
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
	certPEM, keyPEM := id.certKeyPEM()
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
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
	defer conn.Close()

	enc := &safeEncoder{enc: json.NewEncoder(conn)}
	dec := json.NewDecoder(bufio.NewReader(conn))

	if err := enc.Encode(proto.Envelope{Type: proto.MsgHello, Hello: &proto.Hello{ServerID: id.ServerID, AgentVersion: agentVersion}}); err != nil {
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

	// Scoped to this connection, not the process lifetime: without this,
	// heartbeatLoop/renewalLoop launched against the outer ctx would keep
	// running (and leaking a ticker each) after this connection drops and
	// runConnection returns to be retried by main's reconnect loop — a
	// goroutine leak that grows with every reconnect over the agent's
	// uptime.
	connCtx, cancelConn := context.WithCancel(ctx)
	defer cancelConn()

	renewCh := make(chan proto.RenewCert, 1)
	go heartbeatLoop(connCtx, enc)
	go renewalLoop(connCtx, id, dataDir, enc, renewCh)

	for {
		var env proto.Envelope
		if err := dec.Decode(&env); err != nil {
			return err
		}
		switch env.Type {
		case proto.MsgTask:
			if env.Task != nil {
				go handleTask(connCtx, enc, reg, *env.Task)
			}
		case proto.MsgRenewCert:
			if env.RenewCert != nil {
				select {
				case renewCh <- *env.RenewCert:
				default:
					// A previous response is still unconsumed (shouldn't
					// happen — renewalLoop only ever has one request in
					// flight at a time); drop rather than block the read
					// loop on a stale slot.
				}
			}
		}
	}
}

// renewalLoop periodically checks id's current certificate against
// renewalThreshold and, once due, requests a fresh one over the already-
// authenticated connection (enc), waiting on renewCh for the gateway's
// reply. It never blocks the read loop that feeds renewCh: a slow or absent
// reply just means this cycle's attempt times out and the next scheduled
// check tries again.
func renewalLoop(ctx context.Context, id *identity, dataDir string, enc *safeEncoder, renewCh <-chan proto.RenewCert) {
	ticker := time.NewTicker(renewalCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			currentCertPEM, _ := id.certKeyPEM()
			cert, err := parseCertPEM(currentCertPEM)
			if err != nil {
				log.Printf("renewal check: could not parse current certificate: %v", err)
				continue
			}
			if !needsRenewal(cert, time.Now(), renewalThreshold) {
				continue
			}
			log.Printf("client certificate expires %s, requesting renewal", cert.NotAfter.Format(time.RFC3339))

			keyPEM, csrPEM, err := generateRenewalCSR()
			if err != nil {
				log.Printf("renewal: generate CSR: %v", err)
				continue
			}
			if err := enc.Encode(proto.Envelope{Type: proto.MsgRenewCSR, RenewCSR: &proto.RenewCSR{CSRPEM: string(csrPEM)}}); err != nil {
				log.Printf("renewal: send request: %v", err)
				continue
			}

			select {
			case rc := <-renewCh:
				if err := persistRenewedIdentity(dataDir, id, []byte(rc.CertPEM), keyPEM); err != nil {
					// The old certificate is still valid (overlap window —
					// see gateway.renewAgentCert), so this is a retry on the
					// next check, not an outage.
					log.Printf("renewal: persist new identity: %v", err)
					continue
				}
				log.Printf("client certificate renewed, new serial=%s (takes effect on next reconnect)", rc.Serial)
			case <-time.After(30 * time.Second):
				log.Printf("renewal: no response from gateway within 30s, will retry next cycle")
			case <-ctx.Done():
				return
			}
		}
	}
}

func handleTask(ctx context.Context, enc *safeEncoder, reg capabilities.Registry, task proto.Task) {
	send := func(ev proto.TaskEvent) {
		ev.TaskID = task.ID
		ev.At = time.Now().UTC()
		_ = enc.Encode(proto.Envelope{Type: proto.MsgTaskEvent, TaskEvent: &ev})
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

func heartbeatLoop(ctx context.Context, enc *safeEncoder) {
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
			_ = enc.Encode(proto.Envelope{Type: proto.MsgHeartbeat, Heartbeat: &hb})
		}
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
