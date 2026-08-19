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

// certRenewalThreshold is how much remaining certificate lifetime triggers
// a renewal attempt. Certificates are issued for 30 days, so renewing with
// 10 days left gives roughly a third of the lifetime as headroom: a server
// that is offline, unreachable, or failing to renew for any other reason
// has a week and a half of retries — one per reconnect — before its
// identity actually expires, instead of a single all-or-nothing attempt.
const certRenewalThreshold = 10 * 24 * time.Hour

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
	defer conn.Close()

	out := &sender{enc: json.NewEncoder(conn)}
	dec := json.NewDecoder(bufio.NewReader(conn))

	if err := out.send(proto.Envelope{Type: proto.MsgHello, Hello: &proto.Hello{ServerID: id.ServerID, AgentVersion: agentVersion}}); err != nil {
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

	go heartbeatLoop(ctx, out)

	// pendingRenewalKey holds the private key of an in-flight renewal
	// between sending the CSR and receiving the signed certificate. It is
	// kept in memory only — it becomes the agent's identity on disk in
	// handleRenewResponse, and is discarded if the connection drops first
	// (the next connection simply starts a fresh renewal).
	var pendingRenewalKey []byte
	if maybeRequestRenewal(id, out) {
		var csrPEM []byte
		csrPEM, pendingRenewalKey, err = newRenewalCSR()
		if err != nil {
			log.Printf("certificate renewal: could not build request: %v", err)
			pendingRenewalKey = nil
		} else if err := out.send(proto.Envelope{
			Type: proto.MsgRenewRequest, RenewRequest: &proto.RenewRequest{CSRPEM: string(csrPEM)},
		}); err != nil {
			return err
		}
	}

	for {
		var env proto.Envelope
		if err := dec.Decode(&env); err != nil {
			return err
		}
		switch env.Type {
		case proto.MsgTask:
			if env.Task != nil {
				go handleTask(ctx, out, reg, *env.Task)
			}
		case proto.MsgRenewResponse:
			if env.RenewResponse != nil {
				handleRenewResponse(dataDir, out, env.RenewResponse, pendingRenewalKey)
				pendingRenewalKey = nil
			}
		}
	}
}

// sender serializes writes to the connection. Heartbeats, task events, and
// renewal messages are all produced by different goroutines; a json.Encoder
// is not safe for concurrent use, and two interleaved encodes would emit a
// corrupt frame that desynchronizes the stream for the rest of the session.
type sender struct {
	mu  sync.Mutex
	enc *json.Encoder
}

func (s *sender) send(env proto.Envelope) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.enc.Encode(env)
}

// maybeRequestRenewal reports whether the agent's certificate is close
// enough to expiry to warrant asking for a successor. A certificate that
// can't be parsed at all is not treated as due for renewal: the agent
// authenticated with it moments ago, so an unreadable certificate here
// means something is wrong with this code path rather than with the
// certificate, and renewing on that basis would be guessing.
func maybeRequestRenewal(id *identity, out *sender) bool {
	notAfter, err := id.certNotAfter()
	if err != nil {
		log.Printf("certificate renewal: could not read current certificate expiry: %v", err)
		return false
	}
	remaining := time.Until(notAfter)
	if remaining > certRenewalThreshold {
		return false
	}
	log.Printf("certificate expires in %s (threshold %s), requesting renewal",
		remaining.Round(time.Hour), certRenewalThreshold)
	return true
}

// handleRenewResponse persists a signed successor certificate and only then
// acknowledges it. The ordering matters: the acknowledgement is what tells
// the control plane to revoke the certificate being replaced, so sending it
// before the new identity is durably on disk would be exactly the way to
// lock this server out of its own control plane.
func handleRenewResponse(dataDir string, out *sender, resp *proto.RenewResponse, keyPEM []byte) {
	if resp.Error != "" {
		log.Printf("certificate renewal refused by control plane: %s", resp.Error)
		return
	}
	if len(keyPEM) == 0 {
		log.Printf("certificate renewal: received a certificate with no matching in-flight request, ignoring")
		return
	}
	if resp.CertPEM == "" {
		log.Printf("certificate renewal: control plane returned an empty certificate, ignoring")
		return
	}

	if err := persistRenewedIdentity(dataDir, []byte(resp.CertPEM), keyPEM, []byte(resp.CAPEM)); err != nil {
		// The old identity is untouched (see persistRenewedIdentity), so
		// this is a retry-next-reconnect situation, not a broken agent.
		log.Printf("certificate renewal: could not persist new identity, keeping the existing one: %v", err)
		return
	}
	if err := out.send(proto.Envelope{Type: proto.MsgRenewAck}); err != nil {
		log.Printf("certificate renewal: new identity is on disk but the confirmation could not be sent: %v", err)
		return
	}
	log.Printf("certificate renewed; the new identity takes effect on the next reconnect")
}

func handleTask(ctx context.Context, out *sender, reg capabilities.Registry, task proto.Task) {
	send := func(ev proto.TaskEvent) {
		ev.TaskID = task.ID
		ev.At = time.Now().UTC()
		_ = out.send(proto.Envelope{Type: proto.MsgTaskEvent, TaskEvent: &ev})
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

func heartbeatLoop(ctx context.Context, out *sender) {
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
			_ = out.send(proto.Envelope{Type: proto.MsgHeartbeat, Heartbeat: &hb})
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
