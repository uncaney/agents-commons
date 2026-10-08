package webhook

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/events"
)

// Envelope is the complete, self-contained HTTP request an agent replays with its own egress: the
// method, the (masked-everywhere-but-here) url, the headers (Standard Webhooks signature included)
// and the exact body that was signed. It is stored verbatim in hook_out so the signature a poller
// reads always matches the body it reads.
type Envelope struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}

// eventLine renders an event as one short, injection-safe line ("<kind> <ref>: <title>").
func eventLine(row events.Row) string {
	s := strings.TrimSpace(row.Kind + " " + row.Ref)
	if t := strings.TrimSpace(row.Title); t != "" {
		s += ": " + t
	}
	return doc.SafeLine(strings.TrimSpace(s))
}

// eventURL links the envelope back to the originating event (never a user-supplied url).
func eventURL(base string, row events.Row) string {
	return base + "/v1/ev?after=" + strconv.FormatInt(row.Seq-1, 10) + "&k=1"
}

// newMsgID is the Standard Webhooks message id (msg_<random>), stable once stored.
func newMsgID() string {
	var b [12]byte
	rand.Read(b[:])
	return "msg_" + hex.EncodeToString(b[:])
}

// sign is the Standard Webhooks v1 signature: base64(HMAC-SHA256(secret, id + "." + ts + "." + body)).
func sign(secret []byte, id string, ts int64, body string) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(id + "." + strconv.FormatInt(ts, 10) + "." + body))
	return "v1," + base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// renderEnvelope builds the signed envelope for one event and one hook format. base is the public
// site URL; now fixes the webhook-timestamp (passed in so tests are deterministic).
func renderEnvelope(format, url string, secret []byte, row events.Row, base string, now time.Time) Envelope {
	id := newMsgID()
	ts := now.Unix()
	line := eventLine(row)
	ct := "application/json"
	var body string
	extra := map[string]string{}
	switch format {
	case "slack":
		body = jsonObj(map[string]any{"text": line})
	case "discord":
		body = jsonObj(map[string]any{"content": line})
	case "ntfy":
		ct = "text/plain; charset=utf-8"
		body = line
		extra["Title"] = doc.SafeLine(strings.TrimSpace(row.Kind + " " + row.Ref))
		extra["Tags"] = doc.SafeLine(row.Kind)
		extra["Click"] = eventURL(base, row)
	case "a2a":
		body = jsonObj(map[string]any{
			"id":        row.Ref,
			"kind":      "task",
			"contextId": "",
			"status":    map[string]any{"state": "working", "timestamp": row.At.UTC().Format(time.RFC3339)},
		})
		extra["X-A2A-Notification-Token"] = doc.SafeLine(string(secret))
	default: // standard
		body = jsonObj(map[string]any{
			"id":        id,
			"timestamp": ts,
			"type":      row.Kind,
			"data": map[string]any{
				"seq": row.Seq, "kind": row.Kind, "ref": row.Ref,
				"title": row.Title, "at": row.At.UTC().Format(time.RFC3339),
			},
		})
	}
	hdr := map[string]string{
		"content-type":      ct,
		"webhook-id":        id,
		"webhook-timestamp": strconv.FormatInt(ts, 10),
		"webhook-signature": sign(secret, id, ts, body),
	}
	for k, v := range extra {
		hdr[k] = v
	}
	return Envelope{Method: "POST", URL: url, Headers: hdr, Body: body}
}

// jsonObj marshals a map to compact JSON (keys sorted by encoding/json for a stable body).
func jsonObj(m map[string]any) string {
	b, _ := json.Marshal(m)
	return string(b)
}

// curlLine renders an envelope as one shell-safe `curl` line: every value is single-quoted with
// embedded single quotes escaped as '\” so a poller can `… | sh` the output safely.
func (e Envelope) curlLine() string {
	var b strings.Builder
	b.WriteString("curl -sS -X ")
	b.WriteString(e.Method)
	for _, k := range sortedKeys(e.Headers) {
		b.WriteString(" -H ")
		b.WriteString(shQuote(k + ": " + e.Headers[k]))
	}
	b.WriteString(" --data-binary ")
	b.WriteString(shQuote(e.Body))
	b.WriteString(" ")
	b.WriteString(shQuote(e.URL))
	return b.String()
}

// shQuote single-quotes s for POSIX sh, escaping embedded single quotes.
func shQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func sortedKeys(m map[string]string) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	// insertion sort keeps the dependency surface tiny; header sets are small.
	for i := 1; i < len(ks); i++ {
		for j := i; j > 0 && ks[j-1] > ks[j]; j-- {
			ks[j-1], ks[j] = ks[j], ks[j-1]
		}
	}
	return ks
}
