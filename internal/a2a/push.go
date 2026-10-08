package a2a

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"

	"ekaii.fr/commons/internal/core"
)

// maxPushCfg caps a push notification config (stored by the hooks package as a pull hook).
const maxPushCfg = 4 << 10

var errPushUnsupported = rpcErr(CodePushUnsup, "err bad push notifications are not supported here: poll tasks/get, stream tasks/resubscribe, or read /v1/hook/<id>/out",
	map[string]any{"err": "bad", "status": 501, "next": []string{"POST /a2a tasks/get", "GET /help"}})

// pushSet is tasks/pushNotificationConfig/set: the config goes to PushConfigFn (a hooks row the
// requester pulls); the gateway never pushes, so the reply names the pull URL in metadata.pull.
func (s *server) pushSet(ctx context.Context, rc *reqCtx, params json.RawMessage) (any, error) {
	var in struct {
		TaskID string          `json:"taskId"`
		Config json.RawMessage `json:"pushNotificationConfig"`
	}
	if err := json.Unmarshal(params, &in); err != nil {
		return nil, rpcErr(CodeParams, "invalid params: "+safe(err.Error(), 80), nil)
	}
	if rc.ident == nil {
		rc.wantPoW = true
		return nil, authErr(core.ErrAuth)
	}
	if err := s.writeAuth(rc.ident); err != nil {
		return nil, err
	}
	n, ok := parseTaskID(in.TaskID)
	if !ok {
		return nil, taskNotFound(in.TaskID)
	}
	if len(in.Config) > maxPushCfg {
		return nil, core.Bad("pushNotificationConfig <= 4 KiB")
	}
	var cfg struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(in.Config, &cfg); err != nil || cfg.URL == "" {
		return nil, rpcErr(CodeParams, "invalid params: pushNotificationConfig.url required", nil)
	}
	if u, err := url.Parse(strings.TrimSpace(cfg.URL)); err != nil || len(cfg.URL) > 512 || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, core.Bad("pushNotificationConfig.url must be an http(s) URL <= 512 (never fetched by the gateway)")
	}
	if PushConfigFn == nil {
		return nil, errPushUnsupported
	}
	pull, err := PushConfigFn(ctx, s.d.DB, rc.ident.Root, taskID(n), in.Config)
	if err != nil {
		return nil, err
	}
	return map[string]any{"taskId": taskID(n), "pushNotificationConfig": in.Config, "metadata": map[string]any{"pull": pull}}, nil
}

// pushGet is tasks/pushNotificationConfig/get through PushConfigGetFn.
func (s *server) pushGet(ctx context.Context, rc *reqCtx, params json.RawMessage) (any, error) {
	var in struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(params, &in); err != nil {
		return nil, rpcErr(CodeParams, "invalid params: "+safe(err.Error(), 80), nil)
	}
	if rc.ident == nil {
		rc.wantPoW = true
		return nil, authErr(core.ErrAuth)
	}
	n, ok := parseTaskID(in.ID)
	if !ok {
		return nil, taskNotFound(in.ID)
	}
	if PushConfigGetFn == nil {
		return nil, errPushUnsupported
	}
	cfg, pull, err := PushConfigGetFn(ctx, s.d.DB, rc.ident.Root, taskID(n))
	if err != nil {
		return nil, err
	}
	if len(cfg) == 0 {
		cfg = json.RawMessage("{}")
	}
	return map[string]any{"taskId": taskID(n), "pushNotificationConfig": cfg, "metadata": map[string]any{"pull": pull}}, nil
}
