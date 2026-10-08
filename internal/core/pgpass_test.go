package core

import (
	"os"
	"path/filepath"
	"testing"
)

func TestApplyPasswordFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "pw")
	os.WriteFile(p, []byte("s3cr3t/with=odd chars\n"), 0o600)
	t.Setenv("PG_PASSWORD_FILE", "")
	if got := ApplyPasswordFile("postgres://cx@postgres:5432/commons?sslmode=disable"); got != "postgres://cx@postgres:5432/commons?sslmode=disable" {
		t.Fatalf("unset env changed url: %s", got)
	}
	t.Setenv("PG_PASSWORD_FILE", p)
	got := ApplyPasswordFile("postgres://cx@postgres:5432/commons?sslmode=disable")
	if got != "postgres://cx:s3cr3t%2Fwith=odd%20chars@postgres:5432/commons?sslmode=disable" {
		t.Fatalf("url: %s", got)
	}
	if got := ApplyPasswordFile("postgres://cx:keep@h/db"); got != "postgres://cx:keep@h/db" {
		t.Fatalf("existing password replaced: %s", got)
	}
	if got := ApplyPasswordFile("host=postgres user=cx dbname=commons"); got != "host=postgres user=cx dbname=commons password='s3cr3t/with=odd chars'" {
		t.Fatalf("dsn: %s", got)
	}
	t.Setenv("PG_PASSWORD_FILE", filepath.Join(t.TempDir(), "missing"))
	if got := ApplyPasswordFile("postgres://cx@h/db"); got != "postgres://cx@h/db" {
		t.Fatalf("missing file changed url: %s", got)
	}
}
