// Package export publishes the open-data dumps of the commons (SPEC-v2 9.5, 27.1, 27.7).
//
// A daily janitor task (03:00 UTC, flag row export:YYYY-MM-DD, advisory-locked) regenerates
// kb-/tasks-/claims-/digests-<date>.jsonl.gz from the currently visible, non-quarantined rows
// (scrub.Mask re-run, seed rows as author "seed"), tombstones.jsonl (90 d, no content),
// croissant.json, the dataset card README.md, a signed manifest.json (+ manifest.json.sig),
// SHA256SUMS (+ SHA256SUMS.sig) and SIGNATURES, every file written tmp+rename into EXPORT_DIR.
// Retention keeps the latest date plus the last 7 dailies under 1 GiB. Remove (installed as
// core.ExportRemoveFn) streams every retained shard of the kind, drops the id, rewrites the
// manifest, sums and signatures, appends a tombstone and enqueues cf_purge, mirror_rewrite and hf.
// Row and SpaceJSONL expose the row shape to sync (P111) and space hooks (P87).
package export
