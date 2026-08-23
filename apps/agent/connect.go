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

// safeEncoder serializes writes to the shared connection encoder. Multiple
// goroutines write to it concurrently (heartbeats, per-task result events,
// and now certificate-renewal requests), and encoding/json.Encoder provides
// no concurrency guarantee of its own for the underlying net.Conn — without
// this, two goroutines encoding at the same instant could interleave bytes
// from two different messages on the wire.
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
// then loops sending periodic heartbeats, executing any Task the gateway
// sends (replying with TaskEvents), and renewing its own client certificate
// ahead of expiry (see renew.go, docs/SECURITY.md §2). The hosted services
// the agent manages (nginx, php-fpm, mariadb, ...) run under systemd
// independent of this connection — see docs/architecture.md §2 — so a
// dropped connection here degrades orchestration/observability only, never
// site serving.
//
// backoff is a pointer into the caller's reconnect-backoff variable
// (main.go): it's reset to a small value once a session is actually
// established, so a connection that drops after being healthy for a long
// time doesn't inherit a stale, grown-large backoff from an earlier,
// unrelated retry sequence.
func runConnection(ctx context.Context, dataDir string, id *identity, reg capabilities.Registry, backoff *time.Duration) error {
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

	// connCtx is scoped to this one connection attempt (cancelled on every
	// return from this function, successful or not) and is what the
	// background goroutines below are tied to — never the caller's
	// long-lived ctx, which spans every reconnect for the life of the
	// process. Using the long-lived ctx here was a latent goroutine leak:
	// each reconnect would start a new heartbeat/renewal goroutine while
	// the previous connection's own goroutines kept running forever
	// (silently failing to write to an already-closed conn) until process
	// shutdown.
	connCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	enc := json.NewEncoder(conn)
	safeEnc := &safeEncoder{enc: enc}
	dec := json.NewDecoder(bufio.NewReader(conn))

	if err := safeEnc.Encode(proto.Envelope{Type: proto.MsgHello, Hello: &proto.Hello{ServerID: id.ServerID, AgentVersion: agentVersion}}); err != nil {
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
	*backoff = time.Second

	go heartbeatLoop(connCtx, safeEnc)

	renewResp := make(chan proto.RenewResponse, 1)
	renewDone := make(chan error, 1)
	go func() { renewDone <- renewalLoop(connCtx, dataDir, id, safeEnc, renewResp) }()

	// The decoder read loop runs in its own goroutine so this function can
	// also select on renewDone: a successful renewal needs to close this
	// connection and force a prompt reconnect (picking up the new
	// certificate) without waiting for the gateway to send something first.
	msgCh := make(chan proto.Envelope, 16)
	readErrCh := make(chan error, 1)
	go func() {
		for {
			var env proto.Envelope
			if err := dec.Decode(&env); err != nil {
				readErrCh <- err
				return
			}
			msgCh <- env
		}
	}()

	for {
		select {
		case env := <-msgCh:
			switch env.Type {
			case proto.MsgTask:
				if env.Task != nil {
					go handleTask(ctx, safeEnc, reg, *env.Task)
				}
			case proto.MsgRenewResponse:
				if env.RenewResponse != nil {
					select {
					case renewResp <- *env.RenewResponse:
					default:
					}
				}
			}
		case err := <-readErrCh:
			return err
		case <-renewDone:
			// renewalLoop only returns (rather than looping forever) in two
			// cases: connCtx was cancelled (already reflected by ctx.Err()
			// below, since connCtx derives from ctx), or a renewal actually
			// succeeded — either way, this connection is done.
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("certificate renewed, reconnecting to use it")
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func handleTask(ctx context.Context, safeEnc *safeEncoder, reg capabilities.Registry, task proto.Task) {
	send := func(ev proto.TaskEvent) {
		ev.TaskID = task.ID
		ev.At = time.Now().UTC()
		_ = safeEnc.Encode(proto.Envelope{Type: proto.MsgTaskEvent, TaskEvent: &ev})
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

func heartbeatLoop(ctx context.Context, safeEnc *safeEncoder) {
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
			_ = safeEnc.Encode(proto.Envelope{Type: proto.MsgHeartbeat, Heartbeat: &hb})
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
