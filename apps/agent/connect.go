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

// renewalCheckInterval and renewalThreshold control the certificate
// auto-renewal loop: every renewalCheckInterval, the agent checks how much
// life its current certificate has left, and renews as soon as fewer than
// renewalThreshold remains. Against the control plane's 30-day agentCertTTL
// (apps/controlplane/ca.go) this renews around day 20, leaving ~10 days and
// ~240 hourly attempts to recover from a control-plane outage, a network
// partition, or a rejected renewal before the old certificate would
// otherwise expire and lock the agent out with no bootstrap token to fall
// back on (see docs/SYSTEM.md known limitations).
const (
	renewalCheckInterval = 1 * time.Hour
	renewalThreshold     = 10 * 24 * time.Hour
	renewalReplyTimeout  = 30 * time.Second
)

// encoder serializes writes to the single mTLS connection: the heartbeat
// loop, every concurrently in-flight task's result, and the cert-renewal
// loop each encode independently, and two Encode calls racing on the
// underlying conn could otherwise interleave their bytes into invalid JSON
// on the wire.
type encoder struct {
	mu  sync.Mutex
	enc *json.Encoder
}

func (e *encoder) Encode(v any) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.enc.Encode(v)
}

// runConnection maintains one mTLS session to the gateway: sends Hello,
// then loops sending periodic heartbeats and executing any Task the
// gateway sends, replying with TaskEvents. The hosted services the agent
// manages (nginx, php-fpm, mariadb, ...) run under systemd independent of
// this connection — see docs/architecture.md §2 — so a dropped connection
// here degrades orchestration/observability only, never site serving.
func runConnection(ctx context.Context, id *identity, reg capabilities.Registry, dataDir string) error {
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

	enc := &encoder{enc: json.NewEncoder(conn)}
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

	// connCtx is cancelled the moment this connection ends (return from this
	// function, any path), which stops heartbeatLoop and certRenewalLoop
	// together rather than leaking them into the next reconnect attempt.
	connCtx, cancelConn := context.WithCancel(ctx)
	defer cancelConn()

	go heartbeatLoop(connCtx, enc)

	renewResp := make(chan proto.RenewResponse, 1)
	go certRenewalLoop(connCtx, enc, renewResp, id, dataDir)

	for {
		var env proto.Envelope
		if err := dec.Decode(&env); err != nil {
			return err
		}
		switch env.Type {
		case proto.MsgTask:
			if env.Task != nil {
				go handleTask(ctx, enc, reg, *env.Task)
			}
		case proto.MsgRenewResponse:
			if env.RenewResponse != nil {
				select {
				case renewResp <- *env.RenewResponse:
				default:
					// certRenewalLoop isn't waiting (already timed out, or
					// this is a stray duplicate) — drop it rather than block
					// the read loop.
				}
			}
		}
	}
}

func handleTask(ctx context.Context, enc *encoder, reg capabilities.Registry, task proto.Task) {
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

func heartbeatLoop(ctx context.Context, enc *encoder) {
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

// certRenewalLoop periodically checks the current identity's certificate
// lifetime and renews it well before expiry (see renewalThreshold's doc
// comment). It runs for the lifetime of one connection (ctx is cancelled
// when the connection ends); a fresh connection after reconnect starts its
// own loop, so there's no cross-connection state to reconcile.
func certRenewalLoop(ctx context.Context, enc *encoder, respCh <-chan proto.RenewResponse, id *identity, dataDir string) {
	maybeRenew := func() {
		notAfter, err := certNotAfter(id.CertPEM)
		if err != nil {
			log.Printf("cert renewal: could not read current certificate expiry: %v", err)
			return
		}
		if time.Until(notAfter) > renewalThreshold {
			return
		}
		if err := renewIdentity(enc, respCh, id, dataDir); err != nil {
			log.Printf("certificate renewal failed, will retry in %s (current cert valid until %s): %v", renewalCheckInterval, notAfter.Format(time.RFC3339), err)
			return
		}
		log.Printf("certificate renewed successfully")
	}

	// Check immediately: an agent that was offline for a while at startup
	// may already be inside the renewal window, and shouldn't wait a full
	// renewalCheckInterval before finding that out.
	maybeRenew()

	ticker := time.NewTicker(renewalCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			maybeRenew()
		}
	}
}

// renewIdentity performs one renewal round-trip: generate a fresh keypair,
// send its CSR over the already-authenticated connection, and durably
// persist the response before updating the in-memory identity. id's fields
// are only mutated after persistRenewedIdentity succeeds, so a failure
// here always leaves both disk and memory on the still-valid previous
// identity — never a state where memory has moved on but disk hasn't (or
// vice versa).
func renewIdentity(enc *encoder, respCh <-chan proto.RenewResponse, id *identity, dataDir string) error {
	key, csrPEM, err := newCSR()
	if err != nil {
		return err
	}
	if err := enc.Encode(proto.Envelope{Type: proto.MsgRenewRequest, RenewRequest: &proto.RenewRequest{CSRPEM: string(csrPEM)}}); err != nil {
		return fmt.Errorf("send renewal request: %w", err)
	}

	select {
	case resp := <-respCh:
		if resp.Error != "" {
			return fmt.Errorf("gateway declined renewal: %s", resp.Error)
		}
		if resp.CertPEM == "" {
			return fmt.Errorf("gateway sent an empty certificate")
		}
		keyDER, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return err
		}
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
		certPEM := []byte(resp.CertPEM)

		if err := persistRenewedIdentity(dataDir, certPEM, keyPEM); err != nil {
			return fmt.Errorf("persist renewed identity: %w", err)
		}
		id.CertPEM = certPEM
		id.KeyPEM = keyPEM
		return nil
	case <-time.After(renewalReplyTimeout):
		return fmt.Errorf("timed out waiting for gateway's renewal response")
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
