package swarm

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/scrub"
)

// Rendezvous and presence (12.3): peers meet on a key the server only ever sees hashed.
const (
	rvTTLDef  = 300
	rvTTLMax  = 900
	rvCapDef  = 16
	rvMaxKey  = 128
	rvMaxData = 1024
)

type rvIn struct {
	Key  string `json:"key"`
	TTL  int    `json:"ttl_s"`
	Cap  int    `json:"cap"`
	Min  int    `json:"min"`
	Data string `json:"data"`
	Wait int    `json:"wait"`
}

type rvPeer struct {
	id, data string
	until    time.Time
}

// khash is HMAC(server secret, key) with a domain-separated key; the key itself is never stored.
func (s *svc) khash(key string) []byte {
	mac := hmac.New(sha256.New, s.rvKey)
	mac.Write([]byte(key))
	return mac.Sum(nil)
}

func (s *svc) rvPeers(ctx context.Context, q core.Q, rvID string) ([]rvPeer, error) {
	rows, err := q.Query(ctx, `SELECT id, data, until FROM rv_peers WHERE rv = $1 AND until > now() ORDER BY until, id`, rvID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []rvPeer
	for rows.Next() {
		var p rvPeer
		if err := rows.Scan(&p.id, &p.data, &p.until); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// rendezvous is POST /v1/rv and op rv: create or join by key, refresh presence on re-post, long-poll
// until peers >= min.
func (s *svc) rendezvous(ctx context.Context, id *core.Ident, in rvIn, grp string) (reply, error) {
	key := scrub.Normalize(in.Key)
	if key == "" || len(key) > rvMaxKey || !doc.OneLine(key) || strings.TrimSpace(key) != key {
		return reply{}, core.Bad("key: 1..128 printable chars")
	}
	ttl, err := checkRange("ttl_s", in.TTL, rvTTLDef, 1, rvTTLMax)
	if err != nil {
		return reply{}, err
	}
	if in.Cap != 0 && (in.Cap < 2 || in.Cap > rvCapDef) {
		return reply{}, core.Bad("cap must be 2..16")
	}
	minPeers, err := checkRange("min", in.Min, 1, 1, rvCapDef)
	if err != nil {
		return reply{}, err
	}
	if err := checkWait(in.Wait); err != nil {
		return reply{}, err
	}
	masked, err := cleanText("data", &in.Data, rvMaxData)
	if err != nil {
		return reply{}, err
	}
	if err := s.frozen("swarm"); err != nil {
		return reply{}, err
	}
	var rvID string
	var capN int
	var until time.Time
	var peers []rvPeer
	err = core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		kh := s.khash(key)
		err := tx.QueryRow(ctx, `SELECT id, cap, until FROM rv WHERE khash = $1 FOR UPDATE`, kh).Scan(&rvID, &capN, &until)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			if err := rootLock(ctx, tx, id.Root); err != nil {
				return err
			}
			if err := liveCap(ctx, tx, id.Root, "rendezvous", `SELECT count(*) FROM rv WHERE owner_root = $1 AND until > now()`); err != nil {
				return err
			}
			c := in.Cap
			if c == 0 {
				c = rvCapDef
			}
			err = tx.QueryRow(ctx, `INSERT INTO rv (id, khash, cap, owner_root, until) VALUES ($1, $2, $3, $4, now() + $5 * interval '1 second')
				ON CONFLICT (khash) DO UPDATE SET until = greatest(rv.until, EXCLUDED.until) RETURNING id, cap, until`,
				core.NewID('x'), kh, c, id.Root, ttl).Scan(&rvID, &capN, &until)
		case err == nil:
			if in.Cap != 0 && in.Cap != capN {
				return core.E(409, "bad", "cap="+strconv.Itoa(capN))
			}
			err = tx.QueryRow(ctx, `UPDATE rv SET until = greatest(until, now() + $2 * interval '1 second') WHERE id = $1 RETURNING until`, rvID, ttl).Scan(&until)
		}
		if err != nil {
			return err
		}
		if minPeers > capN {
			return core.Bad("min must be 1..cap")
		}
		if _, err := tx.Exec(ctx, `DELETE FROM rv_peers WHERE rv = $1 AND until <= now()`, rvID); err != nil {
			return err
		}
		var isPeer bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM rv_peers WHERE rv = $1 AND id = $2)`, rvID, id.ID).Scan(&isPeer); err != nil {
			return err
		}
		if !isPeer {
			var k int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM rv_peers WHERE rv = $1`, rvID).Scan(&k); err != nil {
				return err
			}
			if k >= capN {
				return core.E(409, "full", "cap="+strconv.Itoa(capN))
			}
		}
		if _, err := tx.Exec(ctx, `INSERT INTO rv_peers (rv, id, root, data, until) VALUES ($1, $2, $3, $4, now() + $5 * interval '1 second')
			ON CONFLICT (rv, id) DO UPDATE SET data = EXCLUDED.data, until = EXCLUDED.until`, rvID, id.ID, id.Root, in.Data, ttl); err != nil {
			return err
		}
		peers, err = s.rvPeers(ctx, tx, rvID)
		return err
	})
	if err != nil {
		return reply{}, err
	}
	wake("rv:" + rvID)
	retry := 0
	if len(peers) < minPeers && in.Wait > 0 {
		retry, err = s.poll(ctx, id, grp, in.Wait, "rv:"+rvID, func(ctx context.Context) (bool, error) {
			ps, err := s.rvPeers(ctx, s.d.DB, rvID)
			if err != nil {
				return false, err
			}
			peers = ps
			return len(ps) >= minPeers, nil
		})
		if err != nil {
			return reply{}, err
		}
	}
	head := fmt.Sprintf("ok rv=%s peers=%d%s", rvID, len(peers), maskedField(masked))
	if retry > 0 {
		head += " retry=" + strconv.Itoa(retry)
	}
	return rvReply(head, rvID, peers), nil
}

func rvReply(head, rvID string, peers []rvPeer) reply {
	var sb strings.Builder
	sb.WriteString(head)
	for _, p := range peers {
		fmt.Fprintf(&sb, "\n- %s until=%s", p.id, unix(p.until))
		if p.data != "" {
			sb.WriteString(" " + doc.Indent(p.data))
		}
	}
	return reply{text: sb.String(), next: []doc.Action{doc.GET("/v1/rv/"+rvID, "peers"), doc.POST("/v1/rv", "heartbeat")}}
}

// rvLookup is GET /v1/rv/{id} and op rvg (peers only; the key is never shown).
func (s *svc) rvLookup(ctx context.Context, rvID string) (reply, error) {
	if !core.ValidIDPrefix(rvID, 'x') {
		return reply{}, core.ErrNotFound
	}
	var capN int
	var until time.Time
	err := s.d.DB.QueryRow(ctx, `SELECT cap, until FROM rv WHERE id = $1 AND until > now()`, rvID).Scan(&capN, &until)
	if errors.Is(err, pgx.ErrNoRows) {
		return reply{}, core.ErrNotFound
	}
	if err != nil {
		return reply{}, err
	}
	peers, err := s.rvPeers(ctx, s.d.DB, rvID)
	if err != nil {
		return reply{}, err
	}
	return rvReply(fmt.Sprintf("rv %s peers=%d cap=%d until=%s", rvID, len(peers), capN, unix(until)), rvID, peers), nil
}

// --- HTTP ---------------------------------------------------------------------------------------

func (s *svc) rvArrive(w http.ResponseWriter, r *http.Request) {
	id, err := s.d.AuthWrite(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	var in rvIn
	if err := core.Decode(w, r, bodyMax, &in); err != nil {
		doc.Fail(w, r, err)
		return
	}
	rep, err := s.rendezvous(r.Context(), id, in, s.grp(r))
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	s.send(w, r, rep)
}

func (s *svc) rvGet(w http.ResponseWriter, r *http.Request) {
	if _, err := s.d.Auth(r); err != nil {
		doc.Fail(w, r, err)
		return
	}
	rep, err := s.rvLookup(r.Context(), r.PathValue("id"))
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	s.send(w, r, rep)
}

// IsPeer reports whether root has a live peer in the live rendezvous rvID: the predicate behind the
// x:<rv id> KV namespace (10.3, mem.RendezvousFn) and the rendezvous handover rule (27.4).
func IsPeer(ctx context.Context, q core.Q, rvID, root string) (bool, error) {
	if !core.ValidIDPrefix(rvID, 'x') || !core.ValidIDPrefix(root, 'a') {
		return false, nil
	}
	var ok bool
	err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM rv_peers p JOIN rv r ON r.id = p.rv
		WHERE p.rv = $1 AND p.root = $2 AND p.until > now() AND r.until > now())`, rvID, root).Scan(&ok)
	return ok, err
}

// --- janitor, resolver --------------------------------------------------------------------------

func (s *svc) janRV(ctx context.Context) error {
	for _, st := range []string{`DELETE FROM rv_peers WHERE until <= now()`, `DELETE FROM rv WHERE until <= now()`} {
		if _, err := s.d.DB.Exec(ctx, st); err != nil {
			return err
		}
	}
	return nil
}

// rvResolve maps a live rendezvous id to its type for /x/ (8.3).
func (s *svc) rvResolve(ctx context.Context, id string) (typ, title, url string, ok bool) {
	if !core.ValidIDPrefix(id, 'x') {
		return "", "", "", false
	}
	var live bool
	if err := s.d.DB.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM rv WHERE id = $1 AND until > now())`, id).Scan(&live); err != nil || !live {
		return "", "", "", false
	}
	return "rv", "rendezvous " + id, "/v1/rv/" + id, true
}
