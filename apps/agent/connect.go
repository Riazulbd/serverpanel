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

// runConnection maintains one mTLS session to the gateway: sends Hello,
// then loops sending periodic heartbeats, running a background certificate
// renewal loop, and executing any Task the gateway sends, replying with
// TaskEvents. The hosted services the agent manages (nginx, php-fpm,
// mariadb, ...) run under systemd independent of this connection — see
// docs/architecture.md §2 — so a dropped connection here degrades
// orchestration/observability only, never site serving.
func runConnection(ctx context.Context, dataDir string, id *identity, reg capabilities.Registry) error {
	// Scoped to this one connection attempt (not the process-lifetime ctx)
	// so the heartbeat and renewal goroutines below are guaranteed to stop
	// as soon as this connection ends, instead of leaking until the whole
	// agent process exits.
	connCtx, cancelConn := context.WithCancel(ctx)
	var wg sync.WaitGroup
	// Registered in this order so cancelConn runs before wg.Wait on every
	// return path (defers run LIFO): stop the background loops first, then
	// block until they've actually exited. Without the Wait, the next
	// connection attempt could start reading id.CertPEM/KeyPEM concurrently
	// with a not-yet-stopped renewalLoop goroutine still writing them.
	defer wg.Wait()
	defer cancelConn()

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

	wg.Add(2)
	go func() { defer wg.Done(); heartbeatLoop(connCtx, enc) }()

	renewResp := make(chan proto.CertRenewResp, 1)
	go func() { defer wg.Done(); renewalLoop(connCtx, dataDir, id, enc, renewResp) }()

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
		case proto.MsgCertRenewResp:
			if env.CertRenewResp != nil {
				select {
				case renewResp <- *env.CertRenewResp:
				default:
				}
			}
		}
	}
}

// renewalLoop keeps this agent's client certificate from ever reaching its
// expiry unattended. It renews at two-thirds of the certificate's validity
// window (e.g. day 20 of a 30-day cert), leaving a wide margin for retries
// if the control plane is briefly unreachable, and persists the renewed
// cert/key to disk so the next reconnect (and the next process restart)
// picks it up automatically — see docs/SECURITY.md §2. A renewal request
// rides the already-open, already-authenticated mTLS connection, so it
// needs no separate credential of its own.
func renewalLoop(ctx context.Context, dataDir string, id *identity, enc *json.Encoder, resp <-chan proto.CertRenewResp) {
	const retryDelay = time.Minute
	const respTimeout = 30 * time.Second

	for {
		notBefore, notAfter, err := certValidity(id.CertPEM)
		if err != nil {
			log.Printf("cert auto-renewal disabled: cannot parse current certificate: %v", err)
			return
		}
		wait := time.Until(nextRenewalAt(notBefore, notAfter))
		if wait < 0 {
			wait = 0
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}

		key, csrPEM, err := newKeyAndCSR(id.ServerID)
		if err != nil {
			log.Printf("cert renewal: could not prepare CSR, will retry: %v", err)
			if !sleepOrDone(ctx, retryDelay) {
				return
			}
			continue
		}
		if err := enc.Encode(proto.Envelope{Type: proto.MsgCertRenewReq, CertRenewReq: &proto.CertRenewReq{CSRPEM: string(csrPEM)}}); err != nil {
			// The connection itself is broken; runConnection's read loop
			// will observe the same failure and trigger a reconnect, which
			// spawns a fresh renewalLoop — nothing more to do here.
			log.Printf("cert renewal: could not send request, connection appears down: %v", err)
			return
		}

		select {
		case <-ctx.Done():
			return
		case r := <-resp:
			if r.Error != "" || r.CertPEM == "" {
				log.Printf("cert renewal rejected by control plane: %s", r.Error)
				if !sleepOrDone(ctx, retryDelay) {
					return
				}
				continue
			}
			keyPEM, err := pemEncodeECKey(key)
			if err != nil {
				log.Printf("cert renewal: could not encode new key, will retry: %v", err)
				if !sleepOrDone(ctx, retryDelay) {
					return
				}
				continue
			}
			if err := persistRenewedCert(dataDir, []byte(r.CertPEM), keyPEM); err != nil {
				log.Printf("cert renewal: could not persist new certificate, will retry: %v", err)
				if !sleepOrDone(ctx, retryDelay) {
					return
				}
				continue
			}
			id.CertPEM = []byte(r.CertPEM)
			id.KeyPEM = keyPEM
			log.Printf("certificate renewed; the new one takes effect on the next reconnect")
		case <-time.After(respTimeout):
			log.Printf("cert renewal: no response from control plane within %s, will retry", respTimeout)
			if !sleepOrDone(ctx, retryDelay) {
				return
			}
		}
	}
}

// nextRenewalAt picks when a certificate valid for [notBefore, notAfter]
// should be renewed: two-thirds of the way through its validity window
// (e.g. day 20 of a 30-day cert), leaving a wide margin before expiry for
// retries if the control plane is briefly unreachable.
func nextRenewalAt(notBefore, notAfter time.Time) time.Time {
	return notBefore.Add((notAfter.Sub(notBefore) * 2) / 3)
}

// sleepOrDone waits for d, returning false early (without sleeping the
// remainder) if ctx is cancelled first.
func sleepOrDone(ctx context.Context, d time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}

func handleTask(ctx context.Context, enc *json.Encoder, reg capabilities.Registry, task proto.Task) {
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

func heartbeatLoop(ctx context.Context, enc *json.Encoder) {
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
