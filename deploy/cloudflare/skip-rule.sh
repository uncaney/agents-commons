#!/usr/bin/env bash
# Add (idempotently) a WAF "skip" rule for one hostname in the zone's http_request_firewall_custom
# ruleset, positioned BEFORE the country-block rule so agents.ekaii.fr is reachable from anywhere
# while the rest of the zone stays geo-restricted.
#
# Env: CF_API_TOKEN (Zone > Firewall Services: Edit), ZONE_ID, RULESET_ID (the zone's
#      http_request_firewall_custom ruleset), COUNTRY_RULE_ID (rule to insert before), HOST
# Usage: skip-rule.sh [--dry-run]       (dry run prints the JSON it would send, sends nothing)
# Needs curl + jq. Never prints the token.
set -euo pipefail

DRY=0
[[ "${1:-}" == "--dry-run" || "${1:-}" == "-n" ]] && DRY=1

: "${CF_API_TOKEN:?}" "${ZONE_ID:?}" "${RULESET_ID:?}" "${COUNTRY_RULE_ID:?}" "${HOST:?}"
API="https://api.cloudflare.com/client/v4"

cf() { # method path [json]
  local m=$1 p=$2 body=${3:-}
  local out
  if [[ -n "$body" ]]; then
    out=$(curl -sS -X "$m" "$API$p" -H "Authorization: Bearer $CF_API_TOKEN" -H 'Content-Type: application/json' --data "$body")
  else
    out=$(curl -sS -X "$m" "$API$p" -H "Authorization: Bearer $CF_API_TOKEN")
  fi
  if [[ "$(jq -r '.success' <<<"$out")" != "true" ]]; then
    echo "cloudflare: $m $p failed:" >&2
    jq -c '.errors' <<<"$out" >&2
    return 1
  fi
  printf '%s' "$out"
}

EXPR="(http.host eq \"$HOST\")"
RULE=$(jq -n --arg expr "$EXPR" --arg desc "commons: allow $HOST from any country" --arg before "$COUNTRY_RULE_ID" '{
  description: $desc,
  expression: $expr,
  action: "skip",
  action_parameters: {
    ruleset: "current",
    phases: ["http_request_sbfm", "http_request_firewall_managed"],
    products: ["waf", "uaBlock", "bic", "hot", "securityLevel", "rateLimit", "zoneLockdown"]
  },
  logging: { enabled: true },
  enabled: true,
  position: { before: $before }
}')

if [[ $DRY -eq 1 ]]; then
  echo "DRY RUN: would POST /zones/$ZONE_ID/rulesets/$RULESET_ID/rules" >&2
  jq . <<<"$RULE"
  exit 0
fi

current=$(cf GET "/zones/$ZONE_ID/rulesets/$RULESET_ID")
existing=$(jq -r --arg expr "$EXPR" '.result.rules[]? | select(.expression == $expr and .action == "skip") | .id' <<<"$current" | head -n1)
if [[ -n "$existing" ]]; then
  echo "skip rule already present: $existing (no change)"
  exit 0
fi
if ! jq -e --arg id "$COUNTRY_RULE_ID" '.result.rules[]? | select(.id == $id)' <<<"$current" >/dev/null; then
  echo "COUNTRY_RULE_ID $COUNTRY_RULE_ID not found in ruleset $RULESET_ID; rules are:" >&2
  jq -r '.result.rules[]? | "\(.id)\t\(.action)\t\(.expression)"' <<<"$current" >&2
  exit 1
fi

res=$(cf POST "/zones/$ZONE_ID/rulesets/$RULESET_ID/rules" "$RULE")
new=$(jq -r --arg expr "$EXPR" '.result.rules[] | select(.expression == $expr) | .id' <<<"$res" | head -n1)
echo "skip rule created: $new"
jq -r '.result.rules[] | "\(.id)\t\(.action)\t\(.expression)"' <<<"$res"
