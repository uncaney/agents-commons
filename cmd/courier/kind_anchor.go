package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// anchor (SPEC-v2 17.2, 20): appends one commit per day to the `anchors` branch of the public mirror
// repository, adding the day's signed Merkle roots (ts/roots.txt). The commit carries the previous
// head as its parent and the branch is updated without force, so git history really does anchor the
// roots and the branch is never rewritten (it is excluded from mirror_rewrite). The branch is created
// on the first run. Re-running on the same UTC day is a no-op: it never writes a second commit.
const anchorRootsMax = 8 << 20

func init() {
	Register(&Kind{Name: "anchor", Hosts: []string{"api.github.com"}, Run: runAnchor})
}

func runAnchor(ctx context.Context, e *Env, job *Job) (json.RawMessage, error) {
	if len(job.Payload) > 0 {
		var ignore map[string]any
		if err := json.Unmarshal(job.Payload, &ignore); err != nil {
			return nil, fmt.Errorf("anchor: payload: %w", err)
		}
	}
	repo := strings.TrimSpace(e.Getenv("GITHUB_REPO"))
	token := e.Secret("gh_token")
	if !ghRepoRe.MatchString(repo) || token == "" {
		return nil, errNoGHConfig
	}
	gh := ghClient{e: e, repo: repo, token: token}
	ctx, cancel := context.WithTimeout(ctx, mirrorRunTimeout)
	defer cancel()

	day := e.Now().UTC().Format("2006-01-02")
	msgPrefix := "anchor " + day
	message := msgPrefix + " roots"

	parent, exists, err := gh.getRef(ctx, "anchors")
	if err != nil {
		return nil, err
	}
	baseTree := ""
	if exists {
		treeSha, parentMsg, err := gh.getCommit(ctx, parent)
		if err != nil {
			return nil, err
		}
		baseTree = treeSha
		if strings.HasPrefix(parentMsg, msgPrefix) {
			// Already anchored today: never append a second commit for the same day.
			return json.Marshal(map[string]any{"day": day, "anchored": false, "reason": "already anchored",
				"head": parent, "ref": "anchors"})
		}
	}

	// Fetch the signed daily roots from the gateway and write them as ts/roots.txt.
	resp, err := e.GatewayGet(ctx, "/ts/roots.txt")
	if err != nil {
		return nil, fmt.Errorf("anchor: fetch roots: %w", err)
	}
	roots, err := readAll(resp.Body, anchorRootsMax)
	resp.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("anchor: read roots: %w", err)
	}
	if len(roots) == 0 {
		return nil, fmt.Errorf("anchor: /ts/roots.txt is empty")
	}

	blobSha, err := gh.blob(ctx, roots)
	if err != nil {
		return nil, err
	}
	treeSha, err := gh.tree(ctx, baseTree, []treeEntry{{Path: "ts/roots.txt", Mode: gitBlobMode, Type: "blob", Sha: blobSha}})
	if err != nil {
		return nil, err
	}
	var parents []string
	if exists {
		parents = []string{parent}
	}
	commitSha, err := gh.commit(ctx, message, treeSha, parents)
	if err != nil {
		return nil, err
	}
	// Never force: the anchors branch is append-only.
	created, err := gh.setBranch(ctx, "anchors", commitSha, false)
	if err != nil {
		return nil, err
	}
	e.Log.Info("anchor appended", "day", day, "commit", commitSha, "parent", parent, "created", created, "bytes", len(roots))
	return json.Marshal(map[string]any{"day": day, "anchored": true, "commit": commitSha, "parent": parent,
		"created": created, "ref": "anchors", "bytes": len(roots)})
}
