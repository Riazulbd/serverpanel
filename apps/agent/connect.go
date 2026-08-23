package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
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

// certRenewalThreshold is how far ahead of its own certificate's expiry the
// agent starts asking the gateway to renew it (see renewalLoop below and
// docs/SECURITY.md §2). A third of the 30-day certificate TTL (ca.go
// agentCertTTL) leaves generous room to retry across a multi-day network or
// gateway outage before the cert actually expires and the agent falls back
// to requiring manual re-registration with a fresh bootstrap token.
const certRenewalThreshold = 10 * 24 * time.Hour

// errCertRenewed is returned by runConnection when it deliberately closes
// its own connection after installing a renewed certificate, so main.go's
// reconnect loop can redial immediately (using the now-updated identity)
// instead of waiting out its failure backoff — this is a routine, expected
// disconnect, not an error condition.
var errCertRenewed = errors.New("certificate renewed, reconnecting to activate it")

// runConnection maintains one mTLS session to the gateway: sends Hello,
// then loops sending periodic heartbeats and executing any Task the
// gateway sends, replying with TaskEvents. The hosted services the agent
// manages (nginx, php-fpm, mariadb, ...) run under systemd independent of
// this connection — see docs/architecture.md §2 — so a dropped connection
// here degrades orchestration/observability only, never site serving.
func runConnection(ctx context.Context, id *identity, reg capabilities.Registry) error {
	certPEM, keyPEM := id.currentCert()
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
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

	// Scoped to this one connection (not the agent's whole-process ctx),
	// and always cancelled when runConnection returns, so heartbeatLoop and
	// renewalLoop from a stale connection never keep running — and keep
	// writing to a closed conn's encoder — after a reconnect has already
	// started a fresh pair on the new one.
	connCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	go heartbeatLoop(connCtx, enc)
	renewKeyCh := make(chan []byte, 1)
	go renewalLoop(connCtx, enc, id, renewKeyCh)

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
			if env.RenewResponse == nil {
				continue
			}
			select {
			case keyPEM := <-renewKeyCh:
				if err := id.persistRenewedCert([]byte(env.RenewResponse.CertPEM), keyPEM); err != nil {
					log.Printf("certificate renewal: %v (keeping current certificate)", err)
					continue
				}
				id.setCert([]byte(env.RenewResponse.CertPEM), keyPEM)
				log.Printf("certificate renewed, reconnecting to activate it")
				return errCertRenewed
			default:
				log.Printf("received a renewal response with no matching request in flight, ignoring")
			}
		}
	}
}

// renewalLoop periodically checks whether id's current certificate is
// nearing expiry and, if so, asks the gateway to renew it over this
// already-authenticated session (see docs/SECURITY.md §2 and
// gateway.go handleRenewRequest). It only ever writes to enc; the response
// is read back on runConnection's single reader goroutine and matched up
// with the private key generated here via renewKeyCh — reserving the
// channel's one slot before sending doubles as an in-flight guard so a
// slow-to-answer gateway doesn't get a second, redundant request every tick.
func renewalLoop(ctx context.Context, enc *json.Encoder, id *identity, renewKeyCh chan []byte) {
	ticker := time.NewTicker(6 * time.Hour)
	defer ticker.Stop()

	checkAndRenew := func() {
		certPEM, _ := id.currentCert()
		notAfter, err := certNotAfter(certPEM)
		if err != nil {
			log.Printf("certificate renewal: could not read current certificate expiry: %v", err)
			return
		}
		if time.Until(notAfter) > certRenewalThreshold {
			return
		}
		csrPEM, keyPEM, err := generateKeyAndCSR()
		if err != nil {
			log.Printf("certificate renewal: could not generate request: %v", err)
			return
		}
		select {
		case renewKeyCh <- keyPEM:
			if err := enc.Encode(proto.Envelope{Type: proto.MsgRenewRequest, RenewRequest: &proto.RenewRequest{CSRPEM: string(csrPEM)}}); err != nil {
				log.Printf("certificate renewal: could not send request: %v", err)
				<-renewKeyCh // free the slot; nothing is actually in flight
			}
		default:
			// A renewal request is already in flight awaiting a response.
		}
	}

	// Check once right away, not only after the first tick: an agent that
	// was offline and just reconnected close to (or past) its threshold
	// shouldn't have to wait up to 6 more hours to start renewing.
	checkAndRenew()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			checkAndRenew()
		}
	}
}

// certNotAfter parses the NotAfter timestamp out of a PEM-encoded
// certificate, without requiring the caller to pull in a full TLS/CA
// context — the agent only ever needs this one field to decide whether
// it's time to ask for a renewal.
func certNotAfter(certPEM []byte) (time.Time, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return time.Time{}, fmt.Errorf("invalid certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, err
	}
	return cert.NotAfter, nil
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
