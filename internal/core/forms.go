package core

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// FormToken is the HMAC carried by every HTML <form method=post> (3.7):
// hex(HMAC(secret, "form"|path|YYYY-MM-DD|group))[:32].
func FormToken(secret []byte, path, group string, t time.Time) string {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte("form|" + path + "|" + t.UTC().Format("2006-01-02") + "|" + group))
	return hex.EncodeToString(m.Sum(nil))[:32]
}

// ErrBadForm is the reply to a missing/stale form token or a foreign Origin.
var ErrBadForm = E(403, "bad", "form token")

// FormTokenFor is FormToken for the current request path and client group, today.
func (d *Deps) FormTokenFor(r *http.Request) string {
	return FormToken(d.Cfg.ServerSecret, r.URL.Path, d.IPGroup(r), time.Now())
}

// CheckForm accepts today's or yesterday's token in the ft form field and requires the Origin
// (or Referer) host to be the public host. Callers cap the body (MaxBytes) before calling.
func (d *Deps) CheckForm(r *http.Request) error {
	if r.PostForm == nil {
		if err := r.ParseForm(); err != nil {
			return ErrBadForm
		}
	}
	ft := r.PostFormValue("ft")
	if len(ft) != 32 {
		return ErrBadForm
	}
	now := time.Now()
	ok := false
	for _, t := range []time.Time{now, now.Add(-24 * time.Hour)} {
		want := FormToken(d.Cfg.ServerSecret, r.URL.Path, d.IPGroup(r), t)
		if subtle.ConstantTimeCompare([]byte(want), []byte(ft)) == 1 {
			ok = true
		}
	}
	if !ok {
		return ErrBadForm
	}
	src := r.Header.Get("Origin")
	if src == "" || src == "null" {
		src = r.Header.Get("Referer")
	}
	u, err := url.Parse(src)
	if err != nil || u.Host == "" || !strings.EqualFold(u.Host, d.publicHost(r)) {
		return ErrBadForm
	}
	return nil
}

// publicHost is the host of PUBLIC_URL, or the request Host when unset (tests, local runs).
func (d *Deps) publicHost(r *http.Request) string {
	if u, err := url.Parse(d.Cfg.PublicURL); err == nil && u.Host != "" {
		return u.Host
	}
	return r.Host
}
