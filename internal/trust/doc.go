// Package trust is the standing layer of the commons (SPEC-v2 4.1-4.5, 17.3, 27.4, 27.8): levels
// L0..L3, vote weights, network distinctness by super-group, governance weight, the per-level caps
// table, the super-group collapse SQL, the single indexability predicate, vouches, the reputation
// log and the decay janitor. Every write path consults it; it writes only its own tables
// (vouches, rep_log, rep_decay) and the identities standing columns.
package trust
