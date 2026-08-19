package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
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

// certRenewalWindow / certRenewalCheckInterval govern the agent's
// certificate-rotation policy: with a 30-day certificate TTL (see
// apps/controlplane/gateway.go's agentCertTTL), checking hourly and
// renewing once fewer than 7 days remain leaves ample headroom for a
// renewal attempt to fail, be retried, or even go unnoticed for a while
// without ever risking a certificate actually expiring mid-connection.
const (
	certRenewalWindow        = 7 * 24 * time.Hour
	certRenewalCheckInterval = time.Hour
)

// errCertRenewed is returned by runConnection when it deliberately closed
// a healthy connection because it just renewed its certificate and wants
// to reconnect with the new identity. main's retry loop treats this as a
// reason to redial immediately, not a failure to back off from.
var errCertRenewed = errors.New("certificate renewed, reconnecting with new identity")

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

	enc := json.NewEncoder(conn)
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

	// Heartbeats, task results, and certificate-renewal requests are all
	// written to enc from separate goroutines below; a raw *json.Encoder
	// has no such guarantee, so every write goes through this mutex to
	// avoid interleaving partial JSON writes from concurrent callers onto
	// the same connection (which would corrupt the message stream).
	var writeMu sync.Mutex
	send := func(env proto.Envelope) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		return enc.Encode(env)
	}

	go heartbeatLoop(ctx, send)

	envCh := make(chan proto.Envelope, 8)
	errCh := make(chan error, 1)
	go func() {
		for {
			var env proto.Envelope
			if err := dec.Decode(&env); err != nil {
				errCh <- err
				return
			}
			envCh <- env
		}
	}()

	renewResultCh := make(chan proto.RenewResult, 1)
	var pending *pendingRenewal
	renewalTicker := time.NewTicker(certRenewalCheckInterval)
	defer renewalTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-errCh:
			return err
		case env := <-envCh:
			switch env.Type {
			case proto.MsgTask:
				if env.Task != nil {
					go handleTask(ctx, send, reg, *env.Task)
				}
			case proto.MsgRenewResult:
				if env.RenewResult != nil {
					select {
					case renewResultCh <- *env.RenewResult:
					default:
					}
				}
			}
		case <-renewalTicker.C:
			if pending != nil {
				continue // a renewal is already in flight; wait for its result
			}
			expiry, err := certExpiry(id.CertPEM)
			if err != nil {
				log.Printf("cert renewal: could not parse current certificate: %v", err)
				continue
			}
			if time.Until(expiry) > certRenewalWindow {
				continue
			}
			p, csrPEM, err := startRenewal()
			if err != nil {
				log.Printf("cert renewal: could not prepare new key/CSR: %v", err)
				continue
			}
			if err := send(proto.Envelope{Type: proto.MsgRenew, Renew: &proto.RenewRequest{CSRPEM: string(csrPEM)}}); err != nil {
				log.Printf("cert renewal: could not send request: %v", err)
				continue
			}
			pending = p
			log.Printf("certificate expires %s, requested renewal", expiry.Format(time.RFC3339))
		case result := <-renewResultCh:
			if pending == nil {
				continue
			}
			p := pending
			pending = nil
			if result.Error != "" {
				log.Printf("cert renewal rejected by gateway: %s", result.Error)
				continue
			}
			if err := p.finish(dataDir, id, result.CertPEM); err != nil {
				log.Printf("cert renewal: could not persist new certificate: %v", err)
				continue
			}
			log.Printf("certificate renewed, reconnecting with new identity")
			conn.Close()
			return errCertRenewed
		}
	}
}

func handleTask(ctx context.Context, send func(proto.Envelope) error, reg capabilities.Registry, task proto.Task) {
	sendEvent := func(ev proto.TaskEvent) {
		ev.TaskID = task.ID
		ev.At = time.Now().UTC()
		_ = send(proto.Envelope{Type: proto.MsgTaskEvent, TaskEvent: &ev})
	}

	sendEvent(proto.TaskEvent{Status: proto.TaskRunning, Message: "starting " + task.Capability})

	// Stack installs and app deployments (apt installs, WordPress core
	// download, ...) can legitimately take minutes over a slow VPS network
	// link; a short timeout here would abort a perfectly healthy install.
	taskCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	progress := func(message string) {
		sendEvent(proto.TaskEvent{Status: proto.TaskRunning, Message: message})
	}

	detail, err := reg.Dispatch(taskCtx, task.Capability, task.Params, progress)
	if err != nil {
		sendEvent(proto.TaskEvent{Status: proto.TaskFailed, Message: err.Error()})
		return
	}
	sendEvent(proto.TaskEvent{Status: proto.TaskSucceeded, Message: "ok", Detail: detail})
}

func heartbeatLoop(ctx context.Context, send func(proto.Envelope) error) {
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
			_ = send(proto.Envelope{Type: proto.MsgHeartbeat, Heartbeat: &hb})
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
