package did

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/e2e"
	"ekaii.fr/commons/internal/keys"
	"ekaii.fr/commons/internal/sign"
	"ekaii.fr/commons/internal/testdb"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var testPool *pgxpool.Pool

func TestMain(m *testing.M) {
	ctx := context.Background()
	cleanup := func() {}
	if url := os.Getenv("TEST_DATABASE_URL"); url != "" {
		pool, err := pgxpool.New(ctx, url)
		if err != nil {
			panic(err)
		}
		if err := core.Migrate(ctx, pool); err != nil {
			panic(err)
		}
		testPool, cleanup = pool, pool.Close
	} else if pool, done := testdb.Open("did", core.Migrate); pool != nil {
		testPool, cleanup = pool, done
	} else {
		fmt.Println("TEST_DATABASE_URL/TEST_PG_ADMIN_URL unset: skipping did DB tests")
		os.Exit(0)
	}
	code := m.Run()
	cleanup()
	os.Exit(code)
}

const testSecret = "test-secret-0123456789abcdef"

type tenv struct {
	d   *core.Deps
	srv *httptest.Server
	ip  string
}

func newEnv(t *testing.T) *tenv {
	t.Helper()
	cfg := core.Config{ServerSecret: []byte(testSecret), AdminToken: "adm", SignKID: 1, PowBits: 6,
		DataDir: t.TempDir(), TrustCF: true, PublicURL: "https://agents.example", RegPerHour: 1 << 20}
	d, err := core.NewDeps(context.Background(), cfg, testPool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	if _, err := sign.Init(cfg); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	sign.Register(mux, d)
	keys.Register(mux, d)
	Register(mux, d)
	srv := httptest.NewServer(d.Handler(mux))
	t.Cleanup(srv.Close)
	var b [3]byte
	rand.Read(b[:])
	return &tenv{d: d, srv: srv, ip: fmt.Sprintf("10.%d.%d.%d", b[0], b[1], b[2])}
}

func (e *tenv) get(t *testing.T, path string) (int, []byte) {
	t.Helper()
	req, _ := http.NewRequest("GET", e.srv.URL+path, nil)
	req.Host = "agents.example"
	req.Header.Set("CF-Connecting-IP", e.ip)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	return res.StatusCode, body
}

// rootWithBundle mints a root without PoW and publishes its seq-1 bundle through the registration
// seam, as core's register does. It returns the id and the identity key's public half.
func rootWithBundle(t *testing.T, e *tenv) (id string, ik ed25519.PublicKey) {
	t.Helper()
	ctx := context.Background()
	seed := e2e.NewSeed()
	ik = e2e.IK(seed).Public().(ed25519.PublicKey)
	err := core.Tx(ctx, testPool, func(tx pgx.Tx) error {
		var err error
		id, _, err = core.CreateRoot(ctx, tx, "did-test", e.ip)
		if err != nil {
			return err
		}
		now := time.Now().Unix()
		var rev [32]byte
		rand.Read(rev[:])
		b, err := e2e.NewBundle(seed, e2e.BundleParams{ID: id, Seq: 1, IAT: uint32(now), Exp: uint32(now + 30*86400),
			MailPolicy: e2e.PolicyPlain, MinCS: uint8(e2e.CS1), E0: e2e.Epoch(now), NEK: 5, RevCommit: rev[:]})
		if err != nil {
			return err
		}
		raw, err := b.Sign(e2e.IK(seed), nil, nil)
		if err != nil {
			return err
		}
		enc, _ := json.Marshal(base64.RawURLEncoding.EncodeToString(raw))
		return keys.RegisterBundle(ctx, tx, id, enc)
	})
	if err != nil {
		t.Fatal(err)
	}
	return id, ik
}

func TestDidDocumentShape(t *testing.T) {
	e := newEnv(t)
	code, body := e.get(t, "/.well-known/did.json")
	if code != 200 {
		t.Fatalf("code=%d body=%s", code, body)
	}
	var doc struct {
		ID                 string `json:"id"`
		VerificationMethod []struct {
			ID           string         `json:"id"`
			Type         string         `json:"type"`
			Controller   string         `json:"controller"`
			PublicKeyJwk map[string]any `json:"publicKeyJwk"`
		} `json:"verificationMethod"`
		AssertionMethod []string `json:"assertionMethod"`
		Service         []struct {
			ID, Type, ServiceEndpoint string
		} `json:"service"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("unmarshal: %v (%s)", err, body)
	}
	if doc.ID != "did:web:agents.example" {
		t.Fatalf("id=%q", doc.ID)
	}
	if len(doc.VerificationMethod) == 0 {
		t.Fatal("no verification method")
	}
	vm := doc.VerificationMethod[0]
	if vm.ID != "did:web:agents.example#k1" || vm.Type != "JsonWebKey2020" || vm.Controller != doc.ID {
		t.Fatalf("vm=%+v", vm)
	}
	if vm.PublicKeyJwk["crv"] != "Ed25519" || vm.PublicKeyJwk["kty"] != "OKP" {
		t.Fatalf("jwk=%+v", vm.PublicKeyJwk)
	}
	x, err := base64.RawURLEncoding.DecodeString(fmt.Sprint(vm.PublicKeyJwk["x"]))
	if err != nil || !ed25519.PublicKey(x).Equal(sign.Public()) {
		t.Fatalf("jwk x does not match the signing key (err=%v)", err)
	}
	if len(doc.AssertionMethod) == 0 || doc.AssertionMethod[0] != vm.ID {
		t.Fatalf("assertionMethod=%v", doc.AssertionMethod)
	}
	want := map[string]bool{"did:web:agents.example#a2a": true, "did:web:agents.example#mcp": true, "did:web:agents.example#ld": true}
	for _, s := range doc.Service {
		delete(want, s.ID)
	}
	if len(want) != 0 {
		t.Fatalf("missing services: %v", want)
	}
}

func TestAgentDidFromBundleOr404(t *testing.T) {
	e := newEnv(t)

	// No bundle published: 404 with the exact message.
	code, body := e.get(t, "/a/a234567/did.json")
	if code != 404 || !strings.Contains(string(body), "err notfound no key published") {
		t.Fatalf("missing agent: code=%d body=%s", code, body)
	}

	id, ik := rootWithBundle(t, e)
	code, body = e.get(t, "/a/"+id+"/did.json")
	if code != 200 {
		t.Fatalf("agent did: code=%d body=%s", code, body)
	}
	var doc struct {
		ID                 string   `json:"id"`
		AlsoKnownAs        []string `json:"alsoKnownAs"`
		VerificationMethod []struct {
			ID           string         `json:"id"`
			Type         string         `json:"type"`
			PublicKeyJwk map[string]any `json:"publicKeyJwk"`
		} `json:"verificationMethod"`
		Note string `json:"note"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("unmarshal: %v (%s)", err, body)
	}
	wantDID := "did:web:agents.example:a:" + id
	if doc.ID != wantDID {
		t.Fatalf("id=%q want %q", doc.ID, wantDID)
	}
	if len(doc.AlsoKnownAs) == 0 || doc.AlsoKnownAs[0] != "https://agents.example/a/"+id {
		t.Fatalf("alsoKnownAs=%v", doc.AlsoKnownAs)
	}
	if len(doc.VerificationMethod) != 1 || doc.VerificationMethod[0].Type != "JsonWebKey2020" {
		t.Fatalf("vm=%+v", doc.VerificationMethod)
	}
	x, err := base64.RawURLEncoding.DecodeString(fmt.Sprint(doc.VerificationMethod[0].PublicKeyJwk["x"]))
	if err != nil || !ed25519.PublicKey(x).Equal(ik) {
		t.Fatalf("agent vm key is not the published identity key (err=%v)", err)
	}
	if !strings.Contains(doc.Note, "tofu") {
		t.Fatalf("expected a tofu note for an unwitnessed bundle, got %q", doc.Note)
	}

	// With a witness seam reporting the bundle is witnessed, the tofu note disappears.
	WitnessedFn = func(context.Context, string) bool { return true }
	defer func() { WitnessedFn = nil }()
	_, body = e.get(t, "/a/"+id+"/did.json")
	var d2 struct {
		Note string `json:"note"`
	}
	json.Unmarshal(body, &d2)
	if d2.Note != "" {
		t.Fatalf("witnessed bundle should carry no tofu note, got %q", d2.Note)
	}
}
