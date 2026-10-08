package session

import (
	"context"
	"fmt"
	"strings"
	"time"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/forge"
	"ekaii.fr/commons/internal/mem"
	"ekaii.fr/commons/internal/swarm"
)

// Step is one plan step: a fixed Go struct (DisallowUnknownFields) discriminated by Op. Only the
// fields of the chosen op are read; validate() enforces the required ones. The ops (27.3):
//
//	tdrop{n}          drop task n (every live claim of the root on it)
//	lkrel{name}       release every lock of the root on that name (fence-aware)
//	cp{name,text}     write a checkpoint whose body records what was held + the step text
//	later{text}       self-mail "session <name> expired" + the step text
//	pub{topic,text}   publish to a topic
//	wq{name,body}     push a work-queue item
//	kv{ns,k,v,ttl}    put a KV value (ttl seconds; 0 = package default)
//	tnote{n,text}     add a note to task n
//
// Text fields carry the placeholders {cp} (latest checkpoint id), {name} (session name), {now}
// (RFC3339 time) and {task} (newest live claim, t:<n>), filled server-side when the step runs.
type Step struct {
	Op    string `json:"op"`
	N     int64  `json:"n,omitempty"`
	Name  string `json:"name,omitempty"`
	Text  string `json:"text,omitempty"`
	Topic string `json:"topic,omitempty"`
	Body  string `json:"body,omitempty"`
	NS    string `json:"ns,omitempty"`
	K     string `json:"k,omitempty"`
	V     string `json:"v,omitempty"`
	TTL   int    `json:"ttl,omitempty"`
}

// stepOps is the set of recognised ops (fail closed on anything else).
var stepOps = map[string]bool{
	"tdrop": true, "lkrel": true, "cp": true, "later": true,
	"pub": true, "wq": true, "kv": true, "tnote": true,
}

func badStep(op, why string) error { return core.Bad("plan step " + op + ": " + why) }

// validate checks the step's required fields and bounds every text field (the plan's 4 KiB cap
// still applies to the whole array). It never fetches or scrubs here: the service functions scrub
// as the owner when the step runs.
func (st *Step) validate() error {
	st.Op = strings.TrimSpace(st.Op)
	if !stepOps[st.Op] {
		return core.Bad(fmt.Sprintf("plan step op must be one of tdrop lkrel cp later pub wq kv tnote (got %q)", st.Op))
	}
	tooLong := func(f, s string) error {
		if len(s) > maxText {
			return badStep(st.Op, f+" <= "+fmt.Sprint(maxText)+" bytes")
		}
		return nil
	}
	for f, s := range map[string]string{"text": st.Text, "body": st.Body, "v": st.V} {
		if err := tooLong(f, s); err != nil {
			return err
		}
	}
	switch st.Op {
	case "tdrop", "tnote":
		if st.N <= 0 {
			return badStep(st.Op, "n must be a positive task number")
		}
		if st.Op == "tnote" && strings.TrimSpace(st.Text) == "" {
			return badStep(st.Op, "text required")
		}
	case "lkrel":
		if !validSwarmName(st.Name) {
			return badStep(st.Op, "name required (<= 128 printable chars)")
		}
	case "cp":
		if st.Name == "" || len(st.Name) > 32 || !core.ValidName(st.Name) {
			return badStep(st.Op, "name must match the checkpoint name grammar (<= 32 [A-Za-z0-9._-])")
		}
	case "later":
		// text is optional; the base subject "session <name> expired" is always sent.
	case "pub":
		if !validSwarmName(st.Topic) {
			return badStep(st.Op, "topic required (<= 128 printable chars)")
		}
		if strings.TrimSpace(st.Text) == "" {
			return badStep(st.Op, "text required")
		}
	case "wq":
		if !validSwarmName(st.Name) {
			return badStep(st.Op, "name required (<= 128 printable chars)")
		}
		if strings.TrimSpace(st.Body) == "" {
			return badStep(st.Op, "body required")
		}
	case "kv":
		if st.NS == "" || st.K == "" {
			return badStep(st.Op, "ns and k required")
		}
		if st.TTL < 0 {
			return badStep(st.Op, "ttl must be a non-negative number of seconds")
		}
	}
	return nil
}

// validSwarmName accepts a non-empty, <= 128-byte printable-ASCII swarm name (the full grammar is
// enforced by swarm.ParseName when the step runs as the owner).
func validSwarmName(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// placeholders are the session-scoped substitution values, resolved once per expiry.
type placeholders struct {
	cp, name, now, task string
}

// resolve fills the placeholder values for a session: {cp} newest live checkpoint, {name} session
// name, {now} RFC3339 time, {task} newest live claim (t:<n>). Missing values become "".
func resolvePlaceholders(ctx context.Context, q core.Q, root, name string) placeholders {
	ph := placeholders{name: name, now: time.Now().UTC().Format(time.RFC3339)}
	var cp string
	if err := q.QueryRow(ctx, `SELECT id FROM checkpoints WHERE root = $1 AND expires_at > now()
		ORDER BY created DESC, seq DESC LIMIT 1`, root).Scan(&cp); err == nil {
		ph.cp = cp
	}
	var n int64
	if err := q.QueryRow(ctx, `SELECT n FROM task_claims WHERE root = $1 AND until > now()
		ORDER BY until DESC LIMIT 1`, root).Scan(&n); err == nil {
		ph.task = "t:" + fmt.Sprint(n)
	}
	return ph
}

func (ph placeholders) apply(s string) string {
	if !strings.ContainsRune(s, '{') {
		return s
	}
	return strings.NewReplacer(
		"{cp}", ph.cp, "{name}", ph.name, "{now}", ph.now, "{task}", ph.task,
	).Replace(s)
}

// fire runs one plan step as the owner identity (owner/root), with placeholders filled. It returns
// a short ref describing what it touched; every error is captured by the caller into fired.
func (st *Step) fire(ctx context.Context, q core.Q, sess *sessionRow, ph placeholders) (string, error) {
	switch st.Op {
	case "tdrop":
		return fmt.Sprintf("t:%d", st.N), forge.Drop(ctx, q, st.N, sess.root)
	case "lkrel":
		return "lock:" + st.Name, swarm.ReleaseByOwner(ctx, q, sess.root, st.Name)
	case "cp":
		body := checkpointBody(ctx, q, sess, ph.apply(st.Text))
		cp, _, err := mem.PutCheckpoint(ctx, q, sess.root, sess.owner, st.Name, "interrupted session "+sess.name, body)
		return "cp:" + cp, err
	case "later":
		text := "session " + sess.name + " expired"
		if t := ph.apply(st.Text); strings.TrimSpace(t) != "" {
			text += "\n" + t
		}
		id, err := mem.Later(ctx, q, sess.root, text, time.Now())
		return "later:" + id, err
	case "pub":
		seq, err := swarm.Publish(ctx, q, st.Topic, sess.owner, sess.root, ph.apply(st.Text), "")
		return fmt.Sprintf("pub:%s#%d", st.Topic, seq), err
	case "wq":
		id, err := swarm.Push(ctx, q, st.Name, ph.apply(st.Body), "")
		return fmt.Sprintf("wq:%s#%d", st.Name, id), err
	case "kv":
		ttl := time.Duration(st.TTL) * time.Second
		ver, err := mem.KVPut(ctx, q, sess.root, st.NS, st.K, []byte(ph.apply(st.V)), ttl)
		return fmt.Sprintf("kv:%s/%s=v%d", st.NS, st.K, ver), err
	case "tnote":
		return fmt.Sprintf("t:%d", st.N), forge.AddNoteAs(ctx, q, st.N, sess.owner, sess.root, ph.apply(st.Text))
	}
	return "", core.Bad("unknown op " + st.Op)
}

// checkpointBody builds the cp step body: a header recording the time, what the owner still held
// (live task claims and locks) and the last audit lines, followed by the step text (27.3).
func checkpointBody(ctx context.Context, q core.Q, sess *sessionRow, text string) string {
	ts := time.Now().UTC().Format(time.RFC3339)
	var held []string
	if rows, err := q.Query(ctx, `SELECT n FROM task_claims WHERE root = $1 AND until > now() ORDER BY until DESC LIMIT 10`, sess.root); err == nil {
		for rows.Next() {
			var n int64
			if rows.Scan(&n) == nil {
				held = append(held, fmt.Sprintf("t:%d", n))
			}
		}
		rows.Close()
	}
	if rows, err := q.Query(ctx, `SELECT name FROM locks WHERE root = $1 AND until > now() ORDER BY since DESC LIMIT 10`, sess.root); err == nil {
		for rows.Next() {
			var name string
			if rows.Scan(&name) == nil {
				held = append(held, "lock:"+name)
			}
		}
		rows.Close()
	}
	heldStr := "none"
	if len(held) > 0 {
		heldStr = strings.Join(held, " ")
	}
	var audit []string
	if rows, err := q.Query(ctx, `SELECT op, ref FROM audit WHERE root = $1 ORDER BY ts DESC LIMIT 5`, sess.root); err == nil {
		for rows.Next() {
			var op, ref string
			if rows.Scan(&op, &ref) == nil {
				line := "  " + op
				if ref != "" {
					line += " " + ref
				}
				audit = append(audit, line)
			}
		}
		rows.Close()
	}
	var b strings.Builder
	fmt.Fprintf(&b, "interrupted: %s held: %s; last audit:", ts, heldStr)
	if len(audit) == 0 {
		b.WriteString(" none")
	} else {
		b.WriteString("\n" + strings.Join(audit, "\n"))
	}
	if strings.TrimSpace(text) != "" {
		b.WriteString("\n" + text)
	}
	return b.String()
}
