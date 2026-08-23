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

// syncEncoder serializes writes to the shared connection encoder. Multiple
// goroutines send over the same TLS connection concurrently — the
// heartbeat loop, one goroutine per in-flight task, and the certificate
// renewal checker — and unsynchronized concurrent writes to a net.Conn can
// interleave partial writes and corrupt the newline-delimited JSON stream.
// (The gateway side of this same protocol already guards its writes with
// agentSession.mu; this is the agent-side equivalent.)
type syncEncoder struct {
	mu  sync.Mutex
	enc *json.Encoder
}

func (s *syncEncoder) send(env proto.Envelope) error {
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
	defer conn.Close()

	senc := &syncEncoder{enc: json.NewEncoder(conn)}
	dec := json.NewDecoder(bufio.NewReader(conn))

	if err := senc.send(proto.Envelope{Type: proto.MsgHello, Hello: &proto.Hello{ServerID: id.ServerID, AgentVersion: agentVersion}}); err != nil {
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

	go heartbeatLoop(ctx, senc)

	renewResultCh := make(chan proto.RenewResponse, 1)
	go renewalLoop(ctx, senc, conn.Close, id.CertPEM, dataDir, renewResultCh)

	for {
		var env proto.Envelope
		if err := dec.Decode(&env); err != nil {
			return err
		}
		switch env.Type {
		case proto.MsgTask:
			if env.Task != nil {
				go handleTask(ctx, senc, reg, *env.Task)
			}
		case proto.MsgRenewResponse:
			if env.RenewResponse != nil {
				select {
				case renewResultCh <- *env.RenewResponse:
				default:
				}
			}
		}
	}
}

// certRenewalCheckInterval is how often a live connection checks whether
// its own client certificate is due for proactive renewal. A cert's
// remaining lifetime only shrinks with wall-clock time, not anything
// event-driven, so a coarse interval keeps this effectively free at idle —
// matching the requirement that the agent stay lightweight while idle.
const certRenewalCheckInterval = 1 * time.Hour

// renewalLoop checks, then periodically rechecks, whether this session's
// client certificate has less than a third of its total lifetime
// remaining, and if so requests a fresh one over the already-authenticated
// connection (see gateway.go handleRenewRequest) rather than waiting until
// it actually expires and the agent silently loses connectivity. On
// success the new cert+key pair is persisted to disk and this connection
// is deliberately closed via closeConn: TLS has no way to swap the client
// certificate on a connection whose handshake already completed, so the
// only way to actually start using the new identity is to reconnect —
// which the caller's retry loop (see main.go) does automatically, and
// promptly, since a self-initiated close resets its backoff.
func renewalLoop(ctx context.Context, senc *syncEncoder, closeConn func() error, certPEM []byte, dataDir string, renewResultCh <-chan proto.RenewResponse) {
	notBefore, notAfter, err := certValidity(certPEM)
	if err != nil {
		log.Printf("certificate renewal check disabled: could not parse own certificate: %v", err)
		return
	}
	renewAt := notAfter.Add(-notAfter.Sub(notBefore) / 3)

	check := func() {
		if time.Now().Before(renewAt) {
			return
		}
		log.Printf("client certificate expires %s, requesting renewal", notAfter.Format(time.RFC3339))
		if err := attemptRenewal(senc, dataDir, renewResultCh); err != nil {
			log.Printf("certificate renewal failed, will retry at next check: %v", err)
			return
		}
		log.Printf("certificate renewed successfully; reconnecting to use it")
		closeConn()
	}

	check()

	ticker := time.NewTicker(certRenewalCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			check()
		}
	}
}

// attemptRenewal performs one renewal round trip: generate a new keypair
// and CSR, send it, wait (bounded) for the gateway's response, and persist
// the result. The new private key never leaves the agent — only its public
// half crosses the wire in the CSR, same as at initial registration.
func attemptRenewal(senc *syncEncoder, dataDir string, renewResultCh <-chan proto.RenewResponse) error {
	key, csrPEM, err := generateKeyAndCSR("pending-renewal")
	if err != nil {
		return err
	}

	if err := senc.send(proto.Envelope{Type: proto.MsgRenewRequest, RenewRequest: &proto.RenewRequest{CSRPEM: string(csrPEM)}}); err != nil {
		return fmt.Errorf("send renew request: %w", err)
	}

	select {
	case resp := <-renewResultCh:
		if resp.Error != "" {
			return fmt.Errorf("gateway declined renewal: %s", resp.Error)
		}
		keyDER, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return fmt.Errorf("marshal new key: %w", err)
		}
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
		if err := persistRenewedCert(dataDir, []byte(resp.CertPEM), keyPEM); err != nil {
			return fmt.Errorf("persist renewed certificate: %w", err)
		}
		return nil
	case <-time.After(30 * time.Second):
		return fmt.Errorf("timed out waiting for renewal response")
	}
}

func handleTask(ctx context.Context, senc *syncEncoder, reg capabilities.Registry, task proto.Task) {
	send := func(ev proto.TaskEvent) {
		ev.TaskID = task.ID
		ev.At = time.Now().UTC()
		_ = senc.send(proto.Envelope{Type: proto.MsgTaskEvent, TaskEvent: &ev})
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

func heartbeatLoop(ctx context.Context, senc *syncEncoder) {
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
			_ = senc.send(proto.Envelope{Type: proto.MsgHeartbeat, Heartbeat: &hb})
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
