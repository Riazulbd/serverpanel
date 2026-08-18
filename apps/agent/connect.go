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

// envelopeWriter serializes writes to the connection's shared json.Encoder.
// heartbeatLoop, every concurrent handleTask goroutine, and renewalLoop all
// write to the same underlying net.Conn; encoding without this mutex would
// let two goroutines interleave their output mid-message and corrupt the
// stream for both.
type envelopeWriter struct {
	mu  sync.Mutex
	enc *json.Encoder
}

func (w *envelopeWriter) write(env proto.Envelope) error {
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
func runConnection(ctx context.Context, id *identity, reg capabilities.Registry) error {
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

	writer := &envelopeWriter{enc: json.NewEncoder(conn)}
	dec := json.NewDecoder(bufio.NewReader(conn))

	if err := writer.write(proto.Envelope{Type: proto.MsgHello, Hello: &proto.Hello{ServerID: id.ServerID, AgentVersion: agentVersion}}); err != nil {
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

	renewResp := make(chan proto.RenewResponse, 1)
	go heartbeatLoop(ctx, writer)
	go renewalLoop(ctx, id, writer, renewResp)

	for {
		var env proto.Envelope
		if err := dec.Decode(&env); err != nil {
			return err
		}
		switch env.Type {
		case proto.MsgTask:
			if env.Task != nil {
				go handleTask(ctx, writer, reg, *env.Task)
			}
		case proto.MsgRenewResponse:
			if env.RenewResponse != nil {
				select {
				case renewResp <- *env.RenewResponse:
				default:
					// A previous response is still unconsumed (the
					// requester already gave up on timeout); drop this one
					// rather than block the read loop.
				}
			}
		}
	}
}

func handleTask(ctx context.Context, writer *envelopeWriter, reg capabilities.Registry, task proto.Task) {
	send := func(ev proto.TaskEvent) {
		ev.TaskID = task.ID
		ev.At = time.Now().UTC()
		_ = writer.write(proto.Envelope{Type: proto.MsgTaskEvent, TaskEvent: &ev})
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

func heartbeatLoop(ctx context.Context, writer *envelopeWriter) {
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
			_ = writer.write(proto.Envelope{Type: proto.MsgHeartbeat, Heartbeat: &hb})
		}
	}
}

// renewalLoop periodically checks whether the identity's certificate is
// approaching expiry and, if so, requests a replacement over the live
// session. It checks once immediately on connect (in case a previous
// session died mid-renewal or before a due renewal could even be
// attempted) and then hourly — frequent enough that, combined with the
// 10-day renewal window (certRenewalWindow), a certificate would have to
// fail to renew for roughly 240 consecutive attempts before it actually
// expired.
func renewalLoop(ctx context.Context, id *identity, writer *envelopeWriter, resp <-chan proto.RenewResponse) {
	attemptRenewal(ctx, id, writer, resp)
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			attemptRenewal(ctx, id, writer, resp)
		}
	}
}

func attemptRenewal(ctx context.Context, id *identity, writer *envelopeWriter, resp <-chan proto.RenewResponse) {
	if !dueForRenewal(id.CertPEM) {
		return
	}
	csrPEM, keyPEM, err := buildRenewalCSR(id.ServerID)
	if err != nil {
		log.Printf("cert renewal: could not build CSR: %v", err)
		return
	}
	if err := writer.write(proto.Envelope{Type: proto.MsgRenewRequest, RenewRequest: &proto.RenewRequest{CSRPEM: string(csrPEM)}}); err != nil {
		log.Printf("cert renewal: could not send request: %v", err)
		return
	}

	select {
	case r := <-resp:
		if r.Error != "" {
			log.Printf("cert renewal: control plane declined: %s", r.Error)
			return
		}
		newCertPEM := []byte(r.CertPEM)
		// The control plane binds CommonName to our server ID itself and
		// signs whatever public key our CSR presented, but we still verify
		// the returned certificate actually matches the private key we
		// generated it for before writing anything to disk — a mismatched
		// pair would make every future reconnect attempt fail.
		if _, err := tls.X509KeyPair(newCertPEM, keyPEM); err != nil {
			log.Printf("cert renewal: issued certificate does not match the requested key, discarding: %v", err)
			return
		}
		if err := persistRenewedIdentity(id.DataDir, newCertPEM, keyPEM); err != nil {
			log.Printf("cert renewal: could not persist new identity: %v", err)
			return
		}
		id.CertPEM = newCertPEM
		id.KeyPEM = keyPEM
		expiry, _ := leafExpiry(newCertPEM)
		log.Printf("cert renewal: succeeded, new certificate (expires %s) will be used on next reconnect", expiry.Format(time.RFC3339))
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
