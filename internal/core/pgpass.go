package core

import (
	"net/url"
	"os"
	"strings"
)

// ApplyPasswordFile injects the password read from $PG_PASSWORD_FILE into a DATABASE_URL
// that carries none, so compose can keep the password in a Docker secret. The URL is
// returned unchanged when the env var is unset, the file is empty or a password is
// already present. Both URL (postgres://user@host/db) and keyword DSNs are handled.
func ApplyPasswordFile(dsn string) string {
	p := os.Getenv("PG_PASSWORD_FILE")
	if p == "" {
		return dsn
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return dsn
	}
	pw := strings.TrimSpace(string(b))
	if pw == "" {
		return dsn
	}
	if !strings.Contains(dsn, "://") {
		if strings.Contains(dsn, "password=") {
			return dsn
		}
		return strings.TrimSpace(dsn + " password='" + strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(pw) + "'")
	}
	u, err := url.Parse(dsn)
	if err != nil {
		return dsn
	}
	if _, has := u.User.Password(); has {
		return dsn
	}
	user := "postgres"
	if u.User != nil && u.User.Username() != "" {
		user = u.User.Username()
	}
	u.User = url.UserPassword(user, pw)
	return u.String()
}
