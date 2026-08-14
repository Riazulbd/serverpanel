package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"sync"
	"time"
)

// store is an in-memory stand-in for the control plane's persistent state
// (Postgres, in production — see docs/architecture.md). Kept as a single
// mutex-guarded struct with a narrow method set so swapping the backing
// store later doesn't require touching callers.
type store struct {
	mu sync.Mutex

	servers map[string]*serverRecord
	tokens  map[string]*bootstrapToken // key: sha256(token) hex
	revoked map[string]bool            // key: cert serial (decimal string)
	audit   []auditEntry
	seq     int
}

type serverStatus string

const (
	statusPending      serverStatus = "pending"      // created, awaiting agent registration
	statusConnected    serverStatus = "connected"    // mTLS session currently open
	statusOffline      serverStatus = "offline"      // registered, no active connection
	statusDisconnected serverStatus = "disconnected" // explicitly revoked by the user
)

type serverRecord struct {
	ID            string
	Name          string
	Group         string
	Tags          []string
	Status        serverStatus
	CertSerial    string
	CreatedAt     time.Time
	LastSeen      time.Time
	AgentVer      string
	LastHeartbeat *heartbeatSnapshot
}

type heartbeatSnapshot struct {
	UptimeSecs  int64
	LoadAvg1    float64
	MemUsedPct  float64
	DiskUsedPct float64
	At          time.Time
}

type bootstrapToken struct {
	ServerID  string
	HashHex   string
	ExpiresAt time.Time
	Used      bool
}

type auditEntry struct {
	Seq      int
	At       time.Time
	ServerID string
	Action   string
	Detail   string
}

func newStore() *store {
	return &store{
		servers: map[string]*serverRecord{},
		tokens:  map[string]*bootstrapToken{},
		revoked: map[string]bool{},
	}
}

func (s *store) log(serverID, action, detail string) {
	s.seq++
	s.audit = append(s.audit, auditEntry{Seq: s.seq, At: time.Now().UTC(), ServerID: serverID, Action: action, Detail: detail})
}

// createServer creates a pending server record and a fresh single-use,
// short-lived bootstrap token for it. Only the token's hash is retained;
// the plaintext is returned once, to the caller, for embedding in the
// one-time install command.
func (s *store) createServer(name, group string, tags []string, ttl time.Duration) (id string, token string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	id = randID("srv")
	s.servers[id] = &serverRecord{
		ID: id, Name: name, Group: group, Tags: tags,
		Status: statusPending, CreatedAt: time.Now().UTC(),
	}

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", err
	}
	token = hex.EncodeToString(raw)
	hash := sha256.Sum256([]byte(token))
	hashHex := hex.EncodeToString(hash[:])
	s.tokens[hashHex] = &bootstrapToken{ServerID: id, HashHex: hashHex, ExpiresAt: time.Now().Add(ttl)}

	s.log(id, "server.created", fmt.Sprintf("name=%q group=%q", name, group))
	s.log(id, "bootstrap_token.issued", fmt.Sprintf("expires_at=%s", s.tokens[hashHex].ExpiresAt.Format(time.RFC3339)))
	return id, token, nil
}

// redeemToken atomically validates and consumes a bootstrap token. The
// plaintext token is never logged by this method or its caller — only the
// server ID and outcome are.
func (s *store) redeemToken(token string) (serverID string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	hash := sha256.Sum256([]byte(token))
	hashHex := hex.EncodeToString(hash[:])
	t, ok := s.tokens[hashHex]
	if !ok {
		return "", fmt.Errorf("unknown or already-consumed token")
	}
	if t.Used {
		return "", fmt.Errorf("token already used")
	}
	if time.Now().After(t.ExpiresAt) {
		delete(s.tokens, hashHex)
		return "", fmt.Errorf("token expired")
	}
	t.Used = true
	delete(s.tokens, hashHex) // single-use: consumed tokens are not retained
	return t.ServerID, nil
}

func (s *store) revokeToken(serverID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for h, t := range s.tokens {
		if t.ServerID == serverID {
			delete(s.tokens, h)
		}
	}
	s.log(serverID, "bootstrap_token.revoked", "")
}

func (s *store) markIssuedCert(serverID, serial string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if rec, ok := s.servers[serverID]; ok {
		rec.CertSerial = serial
		rec.Status = statusOffline
	}
	s.log(serverID, "agent.registered", fmt.Sprintf("cert_serial=%s", serial))
}

func (s *store) isRevoked(serial string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.revoked[serial]
}

// revokeServer revokes the server's issued certificate and marks it
// disconnected. Re-connecting requires a brand new bootstrap token —
// there is no path back to trust from a revoked certificate.
func (s *store) revokeServer(serverID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.servers[serverID]
	if !ok {
		return fmt.Errorf("server not found")
	}
	if rec.CertSerial != "" {
		s.revoked[rec.CertSerial] = true
	}
	rec.Status = statusDisconnected
	s.log(serverID, "agent.revoked", fmt.Sprintf("cert_serial=%s", rec.CertSerial))
	return nil
}

func (s *store) setConnected(serverID string, connected bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.servers[serverID]
	if !ok {
		return
	}
	if connected {
		rec.Status = statusConnected
	} else if rec.Status != statusDisconnected {
		rec.Status = statusOffline
	}
	rec.LastSeen = time.Now().UTC()
}

func (s *store) recordHeartbeat(serverID string, hb heartbeatSnapshot) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if rec, ok := s.servers[serverID]; ok {
		rec.LastHeartbeat = &hb
		rec.LastSeen = hb.At
	}
}

func (s *store) get(serverID string) (*serverRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.servers[serverID]
	return rec, ok
}

func (s *store) list() []*serverRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*serverRecord, 0, len(s.servers))
	for _, r := range s.servers {
		out = append(out, r)
	}
	return out
}

func (s *store) auditLog() []auditEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]auditEntry, len(s.audit))
	copy(out, s.audit)
	return out
}

func randID(prefix string) string {
	n, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	return fmt.Sprintf("%s_%x", prefix, n)
}
