package webhook

import (
	"context"
	"encoding/json"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
)

// A2APush implements a2a.PushConfigFn (SPEC-v2 27.7 / P37): a hosted A2A task's push-notification
// config is stored as an outbound hook (fmt a2a) owned by the requester root and watching the task,
// and the pull URL is returned. The gateway itself never pushes (card pushNotifications:false); the
// requester pulls GET /v1/hook/<id>/out and delivers the Task object with its own egress.
func A2APush(ctx context.Context, q core.Q, requesterRoot, taskID string, cfg json.RawMessage) (string, error) {
	var c struct {
		URL   string `json:"url"`
		Token string `json:"token"`
	}
	// The config may be the bare object or {pushNotificationConfig:{…}}.
	_ = json.Unmarshal(cfg, &c)
	if c.URL == "" {
		var wrap struct {
			PNC struct {
				URL   string `json:"url"`
				Token string `json:"token"`
			} `json:"pushNotificationConfig"`
		}
		if json.Unmarshal(cfg, &wrap) == nil {
			c.URL, c.Token = wrap.PNC.URL, wrap.PNC.Token
		}
	}
	if err := validURL(c.URL); err != nil {
		return "", err
	}
	secret := []byte(c.Token)
	if len(secret) == 0 {
		return "", core.Bad("push config needs a token")
	}
	id := core.NewID('h')
	if _, err := q.Exec(ctx, `INSERT INTO hooks (id, root, url, fmt, kinds, tags, q, secret, last_seq)
		VALUES ($1,$2,$3,'a2a','{t}',$4,'',$5, coalesce((SELECT max(seq) FROM events),0))`,
		id, requesterRoot, c.URL, []string{taskID}, secret); err != nil {
		return "", err
	}
	return doc.Base() + "/v1/hook/" + id + "/out", nil
}
