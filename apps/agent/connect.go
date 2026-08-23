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

// connWriter serializes writes to the connection's JSON encoder. Once
// certificate renewal (renew.go) added a second long-lived goroutine that
// writes to the same connection alongside heartbeatLoop, a bare
// *json.Encoder was no longer safe: two Encode calls racing on the same
// net.Conn can interleave their writes and corrupt the newline-delimited
// JSON stream the gateway is decoding.
type connWriter struct {
	mu  sync.Mutex
	enc *json.Encoder
}

func (w *connWriter) send(env proto.Envelope) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.enc.Encode(env)
}

// runConnection maintains one mTLS session to the gateway: sends Hello,
// then loops sending periodic heartbeats and executing any Task the
// gateway sends, replying with TaskEvents. The hosted services the agent
// manages (nginx, php-fpm, mariadb, ...) run under systemd independent of
// this connection — see docs/architecture.md §2 — so a dropped connection
// here degrades orchestration/observability only, never site serving.
//
// It also runs certRenewalLoop (renew.go) for the lifetime of the session:
// when the client certificate this connection authenticated with nears
// expiry, that loop requests, receives, and persists a replacement, then
// deliberately closes conn to force exactly this function to return —
// main's reconnect loop reloads identity from disk before redialing, so the
// next connection uses the freshly issued certificate.
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

	cw := &connWriter{enc: json.NewEncoder(conn)}
	dec := json.NewDecoder(bufio.NewReader(conn))

	if err := cw.send(proto.Envelope{Type: proto.MsgHello, Hello: &proto.Hello{ServerID: id.ServerID, AgentVersion: agentVersion}}); err != nil {
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

	go heartbeatLoop(ctx, cw)

	renewCertCh := make(chan proto.RenewCert, 1)
	go certRenewalLoop(ctx, dataDir, id.CertPEM, conn, cw, renewCertCh)

	for {
		var env proto.Envelope
		if err := dec.Decode(&env); err != nil {
			return err
		}
		switch env.Type {
		case proto.MsgTask:
			if env.Task != nil {
				go handleTask(ctx, cw, reg, *env.Task)
			}
		case proto.MsgRenewCert:
			if env.RenewCert != nil {
				select {
				case renewCertCh <- *env.RenewCert:
				default:
				}
			}
		}
	}
}

func handleTask(ctx context.Context, cw *connWriter, reg capabilities.Registry, task proto.Task) {
	send := func(ev proto.TaskEvent) {
		ev.TaskID = task.ID
		ev.At = time.Now().UTC()
		_ = cw.send(proto.Envelope{Type: proto.MsgTaskEvent, TaskEvent: &ev})
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

func heartbeatLoop(ctx context.Context, cw *connWriter) {
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
			_ = cw.send(proto.Envelope{Type: proto.MsgHeartbeat, Heartbeat: &hb})
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
