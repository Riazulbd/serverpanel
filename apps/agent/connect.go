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

// connWriter serializes writes to the gateway connection. Heartbeats, task
// progress from several concurrently-running tasks, and certificate-renewal
// requests all share one connection; json.Encoder is not safe for
// concurrent use, and two goroutines encoding at once can interleave
// partial JSON on the wire and desynchronize the gateway's decoder for the
// rest of the session.
type connWriter struct {
	mu  sync.Mutex
	enc *json.Encoder
}

func (w *connWriter) Send(env proto.Envelope) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.enc.Encode(env)
}

// renewCheckInterval is how often a long-lived connection re-checks whether
// its certificate is close enough to expiry to renew. Certificates are
// valid for weeks, so this is deliberately infrequent — the check itself is
// a cheap in-memory comparison, and a connection that drops sooner
// re-checks on reconnect anyway.
const renewCheckInterval = 6 * time.Hour

// runConnection maintains one mTLS session to the gateway: sends Hello,
// then loops sending periodic heartbeats and executing any Task the
// gateway sends, replying with TaskEvents. The hosted services the agent
// manages (nginx, php-fpm, mariadb, ...) run under systemd independent of
// this connection — see docs/architecture.md §2 — so a dropped connection
// here degrades orchestration/observability only, never site serving.
func runConnection(ctx context.Context, id *identity, dataDir string, reg capabilities.Registry, gate *renewalGate) error {
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

	w := &connWriter{enc: json.NewEncoder(conn)}
	dec := json.NewDecoder(bufio.NewReader(conn))

	if err := w.Send(proto.Envelope{Type: proto.MsgHello, Hello: &proto.Hello{ServerID: id.ServerID, AgentVersion: agentVersion}}); err != nil {
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

	connCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	go heartbeatLoop(connCtx, w)

	// pendingKeyPEM holds the private key whose CSR is currently outstanding.
	// It is only written to disk once the matching signed certificate comes
	// back, so an unanswered renewal request leaves the on-disk identity
	// completely untouched.
	var pendingKeyPEM []byte
	requestRenewal := func() {
		if pendingKeyPEM != nil || !certNeedsRenewal(id.CertPEM, time.Now()) {
			return
		}
		if !gate.allow(time.Now()) {
			log.Print("certificate still reads as near expiry right after a renewal; " +
				"holding off rather than reconnecting in a loop (check this server's system clock)")
			return
		}
		csrPEM, keyPEM, err := newRenewalCSR()
		if err != nil {
			log.Printf("could not prepare certificate renewal: %v", err)
			return
		}
		if err := w.Send(proto.Envelope{
			Type: proto.MsgCertRenewRequest, CertRenewRequest: &proto.CertRenewRequest{CSRPEM: string(csrPEM)},
		}); err != nil {
			log.Printf("could not send certificate renewal request: %v", err)
			return
		}
		pendingKeyPEM = keyPEM
		log.Printf("certificate approaching expiry; requested renewal")
	}

	// renewCh moves the periodic check onto the single goroutine that owns
	// pendingKeyPEM, rather than mutating it from a timer goroutine.
	renewCh := make(chan struct{}, 1)
	go func() {
		ticker := time.NewTicker(renewCheckInterval)
		defer ticker.Stop()
		for {
			select {
			case <-connCtx.Done():
				return
			case <-ticker.C:
				select {
				case renewCh <- struct{}{}:
				default:
				}
			}
		}
	}()

	requestRenewal()

	// The decoder must be read from exactly one goroutine, so incoming
	// messages and the renewal timer are multiplexed here rather than by
	// reading the connection from more than one place.
	decoded := make(chan proto.Envelope)
	decodeErr := make(chan error, 1)
	go func() {
		for {
			var env proto.Envelope
			if err := dec.Decode(&env); err != nil {
				decodeErr <- err
				return
			}
			select {
			case decoded <- env:
			case <-connCtx.Done():
				return
			}
		}
	}()

	for {
		select {
		case <-connCtx.Done():
			return connCtx.Err()
		case err := <-decodeErr:
			return err
		case <-renewCh:
			requestRenewal()
		case env := <-decoded:
			switch env.Type {
			case proto.MsgTask:
				if env.Task != nil {
					go handleTask(connCtx, w, reg, *env.Task)
				}
			case proto.MsgCertRenewResponse:
				if env.CertRenewResponse == nil {
					continue
				}
				resp := env.CertRenewResponse
				if resp.Error != "" {
					log.Printf("gateway refused certificate renewal: %s", resp.Error)
					pendingKeyPEM = nil
					continue
				}
				if pendingKeyPEM == nil {
					log.Print("ignoring an unsolicited certificate renewal response")
					continue
				}
				if err := persistRenewedIdentity(dataDir, id.ServerID, id.GatewayAddr, resp.Serial,
					[]byte(resp.CertPEM), pendingKeyPEM, []byte(resp.CAPEM)); err != nil {
					// The previous identity is untouched, so this is
					// recoverable: the next connection asks again.
					log.Printf("could not persist renewed certificate (keeping the existing one): %v", err)
					pendingKeyPEM = nil
					continue
				}
				log.Printf("renewed certificate persisted (serial=%s, valid until %s)", resp.Serial, resp.NotAfter.Format(time.RFC3339))
				return errIdentityRenewed
			}
		}
	}
}

func handleTask(ctx context.Context, w *connWriter, reg capabilities.Registry, task proto.Task) {
	send := func(ev proto.TaskEvent) {
		ev.TaskID = task.ID
		ev.At = time.Now().UTC()
		_ = w.Send(proto.Envelope{Type: proto.MsgTaskEvent, TaskEvent: &ev})
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

func heartbeatLoop(ctx context.Context, w *connWriter) {
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
			_ = w.Send(proto.Envelope{Type: proto.MsgHeartbeat, Heartbeat: &hb})
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
