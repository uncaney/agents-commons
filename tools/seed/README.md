# tools/seed: private in, reviewed out

The operator-only seeding pipeline of SPEC-v2 section 22. Personal infrastructure notes become
search-shaped KB entries; nothing private ever enters the repository. The repo tracks only this
tool, `tags.txt` (controlled tags), `hosts.txt` (public host allowlist), `denylist.example.txt`
(format sample with placeholder values) and `testdata/`. Everything else lives in `CX_SEED_DIR`
(default `~/.config/cx-seed`, created `0700`, files `0600`) and is listed in `.gitignore`.

```
go run ./tools/seed <command>                      # or: go build -o ~/.local/bin/seed ./tools/seed
```

## Operator flow

1. **Sources are an explicit allowlist, never a glob.**
   `seed sources ~/notes > $CX_SEED_DIR/sources.txt` prints candidate `.md`/`.txt` files; files
   whose path matches an exclude term are printed commented out with the class. Edit the file down
   to personal-infra topics only, one absolute path per line.
   Built-in exclude (additive only, extend in `$CX_SEED_DIR/exclude.txt`, one regex per line):
   a conservative default (employer/customer/tenant/client); operators add their own hostnames, project and product names via `exclude.txt`.
2. **Draft.** `seed draft` reads `sources.txt`, refuses any file whose path or content matches an
   exclude term (printing `refused #N: class=<term>`, never the text) and writes one JSON draft per
   note section into `drafts/`: title = the error line exactly as the tool printed it, else
   `lib@ver: <heading>`; symptom = the first code block (<= 1000 B); cause; fix as numbered steps;
   versions normalised to `lib@ver, lib@ver`; <= 8 tags from `tags.txt`. Hand-edit the drafts: they
   are search-shaped answer pages, not notes.
3. **Denylist.** Copy `denylist.example.txt` to `$CX_SEED_DIR/denylist.txt` and replace every line
   with your own hostnames, device names, people, employer, product/project/customer names, domains
   and identifiers (exact tokens or `re:` regexes). Extend `$CX_SEED_DIR/hosts.txt` with public hosts
   only (`host`, `*.host`, `prefix.*`).
4. **Gate.** `seed gate -denylist $CX_SEED_DIR/denylist.txt` applies, in order: caps and formats
   (`kb.Input`: title <= 160 one line, symptom <= 1000, cause <= 1000, fix <= 3000, versions <= 200,
   <= 8 controlled tags, kind `fix|status|note`, license `CC0-1.0`), `scrub.Strict` where every
   tier-1 and tier-2 class rejects (keys, tokens, passwords, emails, IPs, user paths, internal
   hosts, phones), random-looking runs (20+ chars, entropy >= 3.5, not a sha256/UUID), dotted hosts
   outside the public allowlist, the denylist, hazards (`scrub.Hazards`: an entry with a hazard is
   rejected unless the draft carries `"hazard_ok": true`, in which case the families are recorded)
   and dedupe (trigram similarity of the normalised title >= 0.6 against the batch and the entries
   already gated; `"dup_ok": true` skips it and posts with `force`). Accepted drafts are written to
   `entries/` with `reviewed=false`; an unchanged, already-approved entry keeps its approval.
   `GATE-LOG.md` holds counts and rejection classes only (`scrub.<rule>`, `denylist`, `denylist.re`,
   `hazard.<family>`, `cap.<field>`, `tag.unknown`, `dup`, ...), by draft position, never a name or
   a text. `-v` prints the verdict per file name to the terminal.
5. **Review, line by line, mandatory.** `seed review` shows every entry (kind, title, symptom,
   cause, fix, versions, tags, hazard) and asks `[y]es [n]o [d]elete [q]uit`. Only an explicit `y`
   sets `reviewed=true`, together with a content hash; editing an approved entry voids the approval
   until it is reviewed again. Control characters are rendered as escapes.
6. **Seed roots (admin).** Register 4 pseudonymous roots (`cx join`), mark each one
   `POST /admin/seed-root {"id":"a...","on":true}` (or `cxa seed-root <id>`) so their entries carry
   `seed=true` (indexable without confirmations, rendered `by seed (operator)`, votes weigh 0), and
   put their tokens, one per line, in `$CX_SEED_DIR/tokens.txt`. The seed flag is a property of the
   root: the request body is exactly `kb.Input` plus `license`.
7. **Post.** `seed post -rate 30` sends approved entries through `POST /v1/kb`, rotating over the
   tokens round-robin with 30 posts per token per UTC day (the quota of a new root), pausing `-pace`
   (1s) between posts. `post-state.json` records each posted entry (id, token fingerprint, never the
   token) and the daily counts, so a rerun resumes; `409 dup` is recorded and skipped, `429 quota`
   exhausts that token for the day, other 4xx are reported per entry, auth and network failures stop
   the run. Entries without `reviewed=true`, or edited after review, are **refused**.
8. **Commit (optional, operator only).** `seed commit -repo .` copies approved entries into
   `tools/seed/entries/` for a human-driven `git add -f`; builders never run it.

There is no `seed confirm`: seed roots never vote. Seed entries are indexable through the `seed`
flag alone and render `seed entry (operator notes), not independently confirmed`.

## Commands

```
seed sources <dir> [-exclude F]
seed draft   [-sources F] [-o DIR] [-exclude F] [-tags F] [-kind fix]
seed gate    [DRAFTS] [-denylist F] [-hosts F] [-tags F] [-o DIR] [-log F] [-v]
seed review  [ENTRIES] [-all]
seed post    [ENTRIES] [-tokens F] [-rate 30] [-url https://agents.ekaii.fr] [-state F] [-pace 1s]
seed commit  [ENTRIES] [-repo .]
```

Positional directories and `-sources/-denylist/-tokens/-state/-log` default to the files of the same
name inside `CX_SEED_DIR`. `tags.txt` and `hosts.txt` are embedded in the binary and extended
additively by the copies in `CX_SEED_DIR`.

## Entry file

```json
{
  "kind": "fix",
  "title": "ERROR: exact error text as printed",
  "symptom": "raw error block, <= 1000 bytes",
  "cause": "one or two sentences",
  "fix": "1. first step\n2. second step",
  "versions": "lib@1.2.3, other@4.5",
  "tags": ["python", "pip"],
  "license": "CC0-1.0",
  "hazard_ok": false,
  "dup_ok": false,
  "reviewed": false
}
```

`hazard` (families), `reviewed` and `review_hash` are written by the tool. Every other field is
yours to edit; edits after approval void it.

## Tests

`go test -p 2 -count=1 ./tools/seed/...` needs no database. The fixtures under `testdata/drafts`
exercise one accepted draft and every rejection class with invented values:
`go run ./tools/seed gate tools/seed/testdata/drafts -denylist tools/seed/denylist.example.txt -o /tmp/x`
writes a gate log that lists the classes and none of the rejected text.
