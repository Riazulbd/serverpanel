package capabilities

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// redactPatterns strips common secret-bearing query parameters, header
// values, and Authorization-style tokens out of log lines before they ever
// leave the agent process — matching docs/product-plan.md's "redaction of
// sensitive data" requirement for anything shipped off the VPS.
var redactPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)([?&](?:token|password|passwd|secret|api[_-]?key|access[_-]?token)=)[^&\s"]+`),
	regexp.MustCompile(`(?i)(Authorization:\s*Bearer\s+)\S+`),
	regexp.MustCompile(`(?i)(Authorization:\s*Basic\s+)\S+`),
}

func redact(line string) string {
	for _, re := range redactPatterns {
		line = re.ReplaceAllString(line, "${1}[redacted]")
	}
	return line
}

const maxTailLines = 1000

// handleLogsTail only ever reads from the fixed, predictable log paths our
// own nginx vhost template writes to (see writeNginxVhost:
// /var/log/nginx/<system_user>.{access,error}.log) — the caller selects a
// site by its system_user, already validated elsewhere as
// agent-controlled, never an arbitrary filesystem path.
func handleLogsTail(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	sysUser, _ := params["system_user"].(string)
	logType, _ := params["log_type"].(string)
	lines := 200
	if v, ok := params["lines"].(float64); ok && v > 0 {
		lines = int(v)
	}
	if lines > maxTailLines {
		lines = maxTailLines
	}
	if sysUser == "" || !strings.HasPrefix(sysUser, "site_") {
		return "", fmt.Errorf("invalid system_user")
	}

	var path string
	switch logType {
	case "access":
		path = "/var/log/nginx/" + sysUser + ".access.log"
	case "error":
		path = "/var/log/nginx/" + sysUser + ".error.log"
	default:
		return "", fmt.Errorf("log_type must be \"access\" or \"error\"")
	}

	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open log: %w", err)
	}
	defer f.Close()

	// Simple bounded-memory tail: read the whole file's lines into a ring
	// buffer sized to the request. Phase 1 log files are rotated
	// (logrotate) well before this becomes a real memory concern; a
	// seek-from-end implementation would be the next optimization if log
	// files grow large between rotations.
	ring := make([]string, 0, lines)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		ring = append(ring, redact(sc.Text()))
		if len(ring) > lines {
			ring = ring[1:]
		}
	}
	return strings.Join(ring, "\n"), nil
}
