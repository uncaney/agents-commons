package pay

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

// backdate moves an agreement's created timestamp into the past (to trip the auto-close janitor).
func (e *tenv) backdateCreated(t *testing.T, id, interval string) {
	t.Helper()
	if _, err := testPool.Exec(context.Background(), `UPDATE agreements SET created = now() - $2::interval WHERE id = $1`, id, interval); err != nil {
		t.Fatal(err)
	}
}

func (e *tenv) expire(t *testing.T, id string) {
	t.Helper()
	if _, err := testPool.Exec(context.Background(), `UPDATE agreements SET until = now() - interval '1 minute' WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
}

func TestOfferAcceptAutoClose(t *testing.T) {
	e := newEnv(t)
	payer, ptok := mkRoot(t, randIP(), 100, 100, 2)
	payee, qtok := mkRoot(t, randIP(), 0, 0, 2)
	conserved(t, e, "start")

	id := e.mkAgreement(t, ptok, payee, 40, 20, randIP())
	if a := e.row(t, id); a.State != "offered" {
		t.Fatalf("state = %s want offered", a.State)
	}
	// Escrow reserved from the payer's transferable credits.
	if c, ear := bal(t, payer); c != 60 || ear != 60 {
		t.Fatalf("payer balance = %d/%d want 60/60", c, ear)
	}
	conserved(t, e, "offered")

	// Only the payee may accept.
	if st, _ := e.do(t, "POST", "/v1/ag/"+id+"/accept", ptok, ""); st != 403 {
		t.Fatalf("payer accept: want 403 got %d", st)
	}
	e.accept(t, id, qtok, randIP())
	if a := e.row(t, id); a.State != "open" {
		t.Fatalf("state = %s want open", a.State)
	}

	// A second offer, left unaccepted past 24 h, is auto-closed and refunded by the janitor.
	id2 := e.mkAgreement(t, ptok, payee, 10, 5, randIP())
	e.backdateCreated(t, id2, "25 hours")
	if err := e.s.janitor(context.Background()); err != nil {
		t.Fatal(err)
	}
	if a := e.row(t, id2); a.State != "closed" {
		t.Fatalf("auto-close state = %s want closed", a.State)
	}
	// The first (open) agreement still holds its escrow; payer got the 10 back.
	if c, ear := bal(t, payer); c != 60 || ear != 60 {
		t.Fatalf("payer after auto-close = %d/%d want 60/60", c, ear)
	}
	conserved(t, e, "after auto-close")
}

func TestChargeIdempotentAndGuarded(t *testing.T) {
	e := newEnv(t)
	payer, ptok := mkRoot(t, randIP(), 100, 100, 2)
	payee, qtok := mkRoot(t, randIP(), 0, 0, 2)
	qip := randIP()
	id := e.mkAgreement(t, ptok, payee, 40, 20, randIP())
	e.accept(t, id, qtok, qip)

	// First charge of key job-17: the payee is paid 10.
	st, body := e.doIP(t, "POST", "/v1/ag/"+id+"/charge", qtok, `{"amount":10,"key":"job-17","ref":"unit"}`, qip)
	if st != 200 || !strings.Contains(body, "used=10/40") {
		t.Fatalf("charge: %d %s", st, body)
	}
	if _, ear := bal(t, payee); ear != 10 {
		t.Fatalf("payee earned = %d want 10", ear)
	}
	// Replaying the same key pays nothing more and is flagged idem=replay.
	st, body = e.doIP(t, "POST", "/v1/ag/"+id+"/charge", qtok, `{"amount":10,"key":"job-17","ref":"unit"}`, qip)
	if st != 200 || !strings.Contains(body, "idem=replay") {
		t.Fatalf("replay: %d %s", st, body)
	}
	if _, ear := bal(t, payee); ear != 10 {
		t.Fatalf("payee earned after replay = %d want 10", ear)
	}
	if a := e.row(t, id); a.Used != 10 {
		t.Fatalf("used after replay = %d want 10", a.Used)
	}
	// The payer's statement lists exactly one charge.
	cs, _ := loadCharges(context.Background(), testPool, id)
	if len(cs) != 1 || cs[0].Key != "job-17" {
		t.Fatalf("charges = %+v want one job-17", cs)
	}
	st, stmt := e.do(t, "GET", "/v1/ag/"+id, ptok, "")
	if st != 200 || strings.Count(stmt, "- job-17") != 1 {
		t.Fatalf("statement: %d %s", st, stmt)
	}
	conserved(t, e, "after idempotent charge")

	// Guard: a charge on a closed agreement is refused.
	if st, _ := e.do(t, "POST", "/v1/ag/"+id+"/close", ptok, ""); st != 200 {
		t.Fatal("close failed")
	}
	if st, body := e.doIP(t, "POST", "/v1/ag/"+id+"/charge", qtok, `{"amount":1,"key":"k2"}`, qip); st != 409 {
		t.Fatalf("charge on closed: want 409 got %d %s", st, body)
	}
	_ = payer
}

func TestPerChargeAndMaxEnforced(t *testing.T) {
	e := newEnv(t)
	_, ptok := mkRoot(t, randIP(), 100, 100, 2)
	payee, qtok := mkRoot(t, randIP(), 0, 0, 2)
	qip := randIP()
	id := e.mkAgreement(t, ptok, payee, 40, 20, randIP())
	e.accept(t, id, qtok, qip)

	// Over per_charge -> 402, nothing drawn or recorded.
	st, body := e.doIP(t, "POST", "/v1/ag/"+id+"/charge", qtok, `{"amount":25,"key":"a"}`, qip)
	if st != 402 {
		t.Fatalf("over per_charge: want 402 got %d %s", st, body)
	}
	if a := e.row(t, id); a.Used != 0 {
		t.Fatalf("used = %d want 0 after rejected charge", a.Used)
	}
	if cs, _ := loadCharges(context.Background(), testPool, id); len(cs) != 0 {
		t.Fatalf("a rejected charge must not leave a charge row: %+v", cs)
	}

	// Draw to the ceiling, then the next unit is refused for exceeding max.
	for _, k := range []string{"u1", "u2"} {
		if st, body := e.doIP(t, "POST", "/v1/ag/"+id+"/charge", qtok, fmt.Sprintf(`{"amount":20,"key":"%s"}`, k), qip); st != 200 {
			t.Fatalf("charge %s: %d %s", k, st, body)
		}
	}
	if a := e.row(t, id); a.Used != 40 {
		t.Fatalf("used = %d want 40", a.Used)
	}
	if st, body := e.doIP(t, "POST", "/v1/ag/"+id+"/charge", qtok, `{"amount":1,"key":"u3"}`, qip); st != 402 {
		t.Fatalf("over max: want 402 got %d %s", st, body)
	}
	if _, ear := bal(t, payee); ear != 40 {
		t.Fatalf("payee earned = %d want 40", ear)
	}
	conserved(t, e, "ceiling reached")
}

func TestCloseRefundsRemainder(t *testing.T) {
	e := newEnv(t)
	payer, ptok := mkRoot(t, randIP(), 100, 100, 2)
	payee, qtok := mkRoot(t, randIP(), 0, 0, 2)
	qip := randIP()
	id := e.mkAgreement(t, ptok, payee, 40, 40, randIP())
	e.accept(t, id, qtok, qip)
	if st, _ := e.doIP(t, "POST", "/v1/ag/"+id+"/charge", qtok, `{"amount":15,"key":"j"}`, qip); st != 200 {
		t.Fatal("charge failed")
	}
	// Payee closes; the unspent 25 returns to the payer as transferable credits.
	st, body := e.doIP(t, "POST", "/v1/ag/"+id+"/close", qtok, "", qip)
	if st != 200 || !strings.Contains(body, "25cr refunded") {
		t.Fatalf("close: %d %s", st, body)
	}
	if c, ear := bal(t, payer); c != 85 || ear != 85 {
		t.Fatalf("payer after close = %d/%d want 85/85", c, ear)
	}
	if _, ear := bal(t, payee); ear != 15 {
		t.Fatalf("payee earned = %d want 15", ear)
	}
	conserved(t, e, "after close refund")
}

func TestTipsCaps(t *testing.T) {
	e := newEnv(t)
	tipper, ttok := mkRoot(t, randIP(), 500, 500, 2)
	payee, _ := mkRoot(t, randIP(), 0, 0, 2)
	conserved(t, e, "start")

	// Credits cap: 50 x 4 = 200 (the daily ceiling), the 5th credit over it -> 429.
	for i := 0; i < 4; i++ {
		if st, body := e.do(t, "POST", "/v1/tip", ttok, fmt.Sprintf(`{"to":"%s","credits":50}`, payee)); st != 200 {
			t.Fatalf("tip %d: %d %s", i, st, body)
		}
	}
	if st, body := e.do(t, "POST", "/v1/tip", ttok, fmt.Sprintf(`{"to":"%s","credits":1}`, payee)); st != 429 || !strings.Contains(body, "tip credits") {
		t.Fatalf("over credits cap: want 429 got %d %s", st, body)
	}
	if _, ear := bal(t, payee); ear != 200 {
		t.Fatalf("payee earned = %d want 200", ear)
	}
	conserved(t, e, "credits cap")

	// Count cap: a fresh tipper can send 20 one-credit tips, the 21st is refused.
	t2, t2tok := mkRoot(t, randIP(), 500, 500, 2)
	for i := 0; i < 20; i++ {
		if st, body := e.do(t, "POST", "/v1/tip", t2tok, fmt.Sprintf(`{"to":"%s","credits":1}`, payee)); st != 200 {
			t.Fatalf("tip %d: %d %s", i, st, body)
		}
	}
	if st, body := e.do(t, "POST", "/v1/tip", t2tok, fmt.Sprintf(`{"to":"%s","credits":1}`, payee)); st != 429 || !strings.Contains(body, "tips 21/20") {
		t.Fatalf("over count cap: want 429 got %d %s", st, body)
	}
	_ = tipper
	_ = t2
	conserved(t, e, "count cap")
}

func TestEarnedOnlyNeverGrant(t *testing.T) {
	e := newEnv(t)
	// A payer with plenty of grant credits but no earned cannot escrow an agreement.
	_, ptok := mkRoot(t, randIP(), 100, 0, 2)
	payee, _ := mkRoot(t, randIP(), 0, 0, 2)
	st, body := e.do(t, "POST", "/v1/ag", ptok, fmt.Sprintf(`{"to":"%s","max":10,"per_charge":5}`, payee))
	if st != 402 || !strings.Contains(body, "earned required") {
		t.Fatalf("grant-only create: want 402 got %d %s", st, body)
	}
	// Likewise a tip needs earned credits.
	if st, body := e.do(t, "POST", "/v1/tip", ptok, fmt.Sprintf(`{"to":"%s","credits":5}`, payee)); st != 402 {
		t.Fatalf("grant-only tip: want 402 got %d %s", st, body)
	}
	// And a charge pays the payee as earned (transferable), never as grant.
	payer2, p2tok := mkRoot(t, randIP(), 100, 100, 2)
	q2, q2tok := mkRoot(t, randIP(), 7, 0, 2) // starts with 7 grant, 0 earned
	qip := randIP()
	id := e.mkAgreement(t, p2tok, q2, 20, 20, randIP())
	e.accept(t, id, q2tok, qip)
	if st, _ := e.doIP(t, "POST", "/v1/ag/"+id+"/charge", q2tok, `{"amount":6,"key":"j"}`, qip); st != 200 {
		t.Fatal("charge failed")
	}
	c, ear := bal(t, q2)
	if c != 13 || ear != 6 {
		t.Fatalf("payee balance = %d/%d want 13/6 (6 earned added on top of 7 grant)", c, ear)
	}
	_ = payer2
	conserved(t, e, "earned-only")
}

func TestLedgerConservationWithAgreements(t *testing.T) {
	e := newEnv(t)
	_, ptok := mkRoot(t, randIP(), 200, 200, 2)
	payee, qtok := mkRoot(t, randIP(), 0, 0, 2)
	tipRecv, _ := mkRoot(t, randIP(), 0, 0, 2)
	qip := randIP()
	conserved(t, e, "start")

	id := e.mkAgreement(t, ptok, payee, 60, 30, randIP())
	conserved(t, e, "offered")
	e.accept(t, id, qtok, qip)
	conserved(t, e, "open")
	if st, _ := e.doIP(t, "POST", "/v1/ag/"+id+"/charge", qtok, `{"amount":30,"key":"a"}`, qip); st != 200 {
		t.Fatal("charge a")
	}
	conserved(t, e, "charge a")
	if st, _ := e.doIP(t, "POST", "/v1/ag/"+id+"/charge", qtok, `{"amount":20,"key":"b"}`, qip); st != 200 {
		t.Fatal("charge b")
	}
	conserved(t, e, "charge b")
	// A tip in flight.
	if st, _ := e.do(t, "POST", "/v1/tip", ptok, fmt.Sprintf(`{"to":"%s","credits":25}`, tipRecv)); st != 200 {
		t.Fatal("tip")
	}
	conserved(t, e, "tip")
	// Expire and auto-close: the remaining 10 refunds.
	e.expire(t, id)
	if err := e.s.janitor(context.Background()); err != nil {
		t.Fatal(err)
	}
	if a := e.row(t, id); a.State != "closed" {
		t.Fatalf("state = %s want closed", a.State)
	}
	conserved(t, e, "closed")
}

func TestMeP2PSplit(t *testing.T) {
	e := newEnv(t)
	_, ptok := mkRoot(t, randIP(), 200, 200, 2)
	payee, qtok := mkRoot(t, randIP(), 0, 0, 2)
	qip := randIP()
	id := e.mkAgreement(t, ptok, payee, 40, 20, randIP())
	e.accept(t, id, qtok, qip)
	if st, _ := e.doIP(t, "POST", "/v1/ag/"+id+"/charge", qtok, `{"amount":18,"key":"j"}`, qip); st != 200 {
		t.Fatal("charge failed")
	}
	// A tip adds to the same p2p total.
	if st, _ := e.do(t, "POST", "/v1/tip", ptok, fmt.Sprintf(`{"to":"%s","credits":12}`, payee)); st != 200 {
		t.Fatal("tip failed")
	}
	// me renders earned=30 (p2p 30): both the charge and the tip count as p2p income.
	st, body := e.doIP(t, "GET", "/v1/me", qtok, "", qip)
	if st != 200 {
		t.Fatalf("me: %d %s", st, body)
	}
	if !strings.Contains(body, "earned=30 (p2p 30)") {
		t.Fatalf("me missing p2p split line:\n%s", body)
	}
}
