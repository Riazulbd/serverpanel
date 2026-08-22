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
	"time"

	"github.com/riazulbd/serverpanel/packages/capabilities"
	"github.com/riazulbd/serverpanel/packages/proto"
)

const agentVersion = "0.1.0-dev"

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

	certRenewed := make(chan proto.RenewCertResult, 1)
	go heartbeatLoop(ctx, enc)
	go certRenewalLoop(ctx, id, enc, certRenewed, conn)

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
		case proto.MsgCertRenewed:
			if env.CertRenewed != nil {
				select {
				case certRenewed <- *env.CertRenewed:
				default:
				}
			}
		}
	}
}

// certRenewalLoop periodically checks the connection's client certificate
// against certRenewalThreshold and, once it's due, requests a fresh one over
// this already-authenticated mTLS session. On success it persists the new
// cert/key (both to disk and into id, so a subsequent reconnect on this same
// process picks it up) and then deliberately closes conn: this forces the
// reconnect loop in main.go to redial with the new certificate immediately,
// proving end-to-end that the rotation actually works rather than assuming
// it and finding out at the next natural disconnect.
func certRenewalLoop(ctx context.Context, id *identity, enc *json.Encoder, results <-chan proto.RenewCertResult, conn net.Conn) {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		notAfter, err := certExpiry(id.CertPEM)
		if err != nil {
			log.Printf("cert renewal: could not parse current certificate: %v", err)
			continue
		}
		if !shouldRenewCert(notAfter, time.Now(), certRenewalThreshold) {
			continue
		}
		log.Printf("client certificate expires %s, requesting renewal", notAfter.Format(time.RFC3339))

		csrPEM, keyPEM, err := generateRenewalCSR(id.ServerID)
		if err != nil {
			log.Printf("cert renewal: %v", err)
			continue
		}
		if err := enc.Encode(proto.Envelope{Type: proto.MsgRenewCert, RenewCert: &proto.RenewCertRequest{CSRPEM: string(csrPEM)}}); err != nil {
			log.Printf("cert renewal: send request: %v", err)
			continue
		}

		select {
		case res := <-results:
			if res.Error != "" {
				log.Printf("cert renewal rejected by control plane: %s", res.Error)
				continue
			}
			if res.CertPEM == "" {
				log.Printf("cert renewal: control plane returned no error but no certificate either")
				continue
			}
			if err := persistRenewedCert(id.DataDir, []byte(res.CertPEM), keyPEM); err != nil {
				log.Printf("cert renewal: %v", err)
				continue
			}
			id.CertPEM = []byte(res.CertPEM)
			id.KeyPEM = keyPEM
			log.Printf("client certificate renewed, reconnecting to activate it")
			conn.Close()
			return
		case <-ctx.Done():
			return
		case <-time.After(30 * time.Second):
			log.Printf("cert renewal: no response from control plane within 30s, will retry")
		}
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
