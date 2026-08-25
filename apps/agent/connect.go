package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
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

// certRenewalCheckInterval and certRenewalWindow govern in-band certificate
// rotation (see certRenewalLoop below): every check interval, the agent
// looks at its current certificate's remaining lifetime and requests a
// fresh one once less than the window remains. Against the control plane's
// 30-day issuance TTL (apps/controlplane/http.go, gateway.go), this renews
// at roughly the 20-day mark, leaving ample margin before expiry even if a
// renewal attempt or two is missed (e.g. the agent was disconnected).
const (
	certRenewalCheckInterval = 6 * time.Hour
	certRenewalWindow        = 10 * 24 * time.Hour
)

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

	// A context scoped to this connection, not the whole process: without
	// this, heartbeatLoop/certRenewalLoop below would keep ticking forever
	// against a dead connection after every reconnect, leaking one goroutine
	// per past connection for the life of the process.
	connCtx, cancelConn := context.WithCancel(ctx)
	defer cancelConn()

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

	go heartbeatLoop(connCtx, enc)

	renewResults := make(chan proto.RenewCertResult, 1)
	go certRenewalLoop(connCtx, enc, renewResults, id, dataDir)

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
		case proto.MsgRenewCertResult:
			if env.RenewCertResult != nil {
				select {
				case renewResults <- *env.RenewCertResult:
				default:
				}
			}
		}
	}
}

// certRenewalLoop periodically checks the in-memory identity's certificate
// expiry and, once inside certRenewalWindow, requests a fresh one over this
// already-authenticated connection. On success it updates id.CertPEM/KeyPEM
// in place (and persists them to disk) so the *next* reconnect — main.go's
// retry loop passes the same *identity across attempts — picks up the new
// pair automatically, with no human intervention and no new bootstrap
// token. It stops when the connection's context is done (including a
// dropped connection, since runConnection's caller cancels nothing itself
// but the goroutine leaks harmlessly until the next Decode error returns
// and the loop is abandoned along with the rest of this connection's
// goroutines — matching heartbeatLoop's existing lifecycle).
func certRenewalLoop(ctx context.Context, enc *json.Encoder, results <-chan proto.RenewCertResult, id *identity, dataDir string) {
	ticker := time.NewTicker(certRenewalCheckInterval)
	defer ticker.Stop()

	checkAndRenew := func() {
		block, _ := pem.Decode(id.CertPEM)
		if block == nil {
			return
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return
		}
		if time.Until(cert.NotAfter) > certRenewalWindow {
			return
		}
		if err := requestCertRenewal(enc, results, id, dataDir); err != nil {
			log.Printf("certificate renewal failed, will retry at next check: %v", err)
			return
		}
		log.Printf("certificate renewed successfully")
	}

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

// requestCertRenewal generates a fresh key/CSR, sends it to the gateway,
// and — on a successful reply — persists and swaps in the new identity.
// The CSR's requested Subject is ignored by the CA (it derives the
// certificate's CommonName from the mTLS-authenticated session's
// server_id, never from caller-supplied data — see gateway.go
// handleRenewCert), so what's set here is informational only.
func requestCertRenewal(enc *json.Encoder, results <-chan proto.RenewCertResult, id *identity, dataDir string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}
	csrTmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: id.ServerID}}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTmpl, key)
	if err != nil {
		return fmt.Errorf("create CSR: %w", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	if err := enc.Encode(proto.Envelope{Type: proto.MsgRenewCert, RenewCert: &proto.RenewCertReq{CSRPEM: string(csrPEM)}}); err != nil {
		return fmt.Errorf("send renewal request: %w", err)
	}

	select {
	case res := <-results:
		if !res.OK {
			return fmt.Errorf("control plane rejected renewal: %s", res.Error)
		}
		keyDER, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return fmt.Errorf("marshal new key: %w", err)
		}
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
		if err := persistRenewedCert(dataDir, []byte(res.CertPEM), keyPEM); err != nil {
			return fmt.Errorf("persist renewed cert: %w", err)
		}
		id.CertPEM = []byte(res.CertPEM)
		id.KeyPEM = keyPEM
		return nil
	case <-time.After(30 * time.Second):
		return fmt.Errorf("timed out waiting for renewal response from gateway")
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
