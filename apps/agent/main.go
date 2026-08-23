// Command serverpanel-agent is the lightweight agent installed on a
// customer VPS. It registers once with a single-use bootstrap token
// (see docs/security-trust-model.md §1), then maintains a persistent,
// mutually-authenticated connection to the control plane and executes only
// the fixed set of capabilities in packages/capabilities — there is no
// arbitrary command-execution entry point anywhere in this binary.
package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/riazulbd/serverpanel/packages/capabilities"
)

func main() {
	apiAddr := flag.String("api", "", "control plane API address, e.g. https://api.serverpanel.example (required for first-time registration)")
	token := flag.String("token", "", "single-use bootstrap token (required for first-time registration; never reused or stored in plaintext)")
	dataDir := flag.String("data-dir", "/etc/serverpanel-agent", "directory holding the agent's persisted identity")
	registerOnly := flag.Bool("register-only", false, "exchange the bootstrap token for a certificate identity, then exit (used once by install.sh so the token is never written into the long-running systemd unit)")
	flag.Parse()

	id, err := loadIdentity(*dataDir)
	if err != nil {
		if *token == "" || *apiAddr == "" {
			log.Fatalf("no existing identity in %s and no -api/-token supplied for first-time registration: %v", *dataDir, err)
		}
		log.Printf("no existing identity found, registering with control plane at %s", *apiAddr)
		id, err = register(*apiAddr, *token, *dataDir)
		if err != nil {
			log.Fatalf("registration failed: %v", err)
		}
		log.Printf("registration succeeded: server_id=%s", id.ServerID)
	} else {
		log.Printf("loaded existing identity: server_id=%s", id.ServerID)
	}

	if *registerOnly {
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	reg := capabilities.Default()

	backoff := time.Second
	for {
		start := time.Now()
		err := runConnection(ctx, id, reg, *dataDir)
		if ctx.Err() != nil {
			log.Println("shutting down")
			return
		}

		if errors.Is(err, errCertRenewed) {
			// The connection was closed deliberately, having already
			// persisted a valid new certificate to disk — reload it so the
			// next dial uses it. loadIdentity failing here would mean the
			// renewal write we just did is somehow unreadable; fall back to
			// the (still valid, just older) in-memory identity rather than
			// crashing the agent over it.
			if fresh, loadErr := loadIdentity(*dataDir); loadErr != nil {
				log.Printf("certificate was renewed but reloading identity failed, retrying with previous credential: %v", loadErr)
			} else {
				id = fresh
			}
		} else {
			log.Printf("connection to gateway lost: %v (retrying in %s)", err, backoff)
		}

		// A connection that stayed up a while was a real, healthy session
		// (including the common case of a renewal-triggered reconnect
		// after weeks of uptime) — don't let backoff stay stuck near its
		// cap from a long time ago for what is effectively a fresh start.
		if time.Since(start) > 30*time.Second {
			backoff = time.Second
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}
