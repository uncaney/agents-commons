#!/usr/bin/env bash
# Create or update a rate-limiting rule for one hostname in the zone's http_ratelimit phase
# entrypoint ruleset: REQS requests per PERIOD seconds per client IP -> block for TIMEOUT seconds.
# Idempotent: the rule is matched by description "commons-rl-<HOST>" and replaced in place; all
# other rules of the entrypoint are preserved.
#
# Env: CF_API_TOKEN, ZONE_ID, HOST [REQS=600] [PERIOD=60] [TIMEOUT=60]
#      Free plan only allows PERIOD=10 and TIMEOUT=10 (block) -> REQS=100 PERIOD=10 TIMEOUT=10.
# Usage: rate-limit.sh [--dry-run]
# Needs curl + jq. Never prints the token.
set -euo pipefail

DRY=0
[[ "${1:-}" == "--dry-run" || "${1:-}" == "-n" ]] && DRY=1

: "${CF_API_TOKEN:?}" "${ZONE_ID:?}" "${HOST:?}"
REQS="${REQS:-600}" PERIOD="${PERIOD:-60}" TIMEOUT="${TIMEOUT:-60}"
API="https://api.cloudflare.com/client/v4"
DESC="commons-rl-$HOST"

cf() { # method path [json]; prints the body even on API failure (caller inspects .success)
  local m=$1 p=$2 body=${3:-}
  if [[ -n "$body" ]]; then
    curl -sS -X "$m" "$API$p" -H "Authorization: Bearer $CF_API_TOKEN" -H 'Content-Type: application/json' --data "$body"
  else
    curl -sS -X "$m" "$API$p" -H "Authorization: Bearer $CF_API_TOKEN"
  fi
}

RULE=$(jq -n --arg host "$HOST" --arg desc "$DESC" --argjson reqs "$REQS" --argjson period "$PERIOD" --argjson timeout "$TIMEOUT" '{
  description: $desc,
  expression: "(http.host eq \($host | tojson))",
  action: "block",
  action_parameters: {
    response: { status_code: 429, content_type: "text/plain", content: "err rate slow down\n" }
  },
  ratelimit: {
    characteristics: ["ip.src", "cf.colo.id"],
    period: $period,
    requests_per_period: $reqs,
    mitigation_timeout: $timeout
  },
  enabled: true
}')

# existing entrypoint (404 = none yet)
cur=$(cf GET "/zones/$ZONE_ID/rulesets/phases/http_ratelimit/entrypoint")
if [[ "$(jq -r '.success' <<<"$cur")" == "true" ]]; then
  others=$(jq -c --arg desc "$DESC" '[.result.rules[]? | select(.description != $desc)
      | del(.id, .version, .last_updated, .ref, .categories)]' <<<"$cur")
else
  if ! jq -e '.errors[]? | select(.code == 10003 or .code == 10000 or .code == 10001 or .code == 10002)' <<<"$cur" >/dev/null; then
    echo "cloudflare: GET entrypoint failed:" >&2
    jq -c '.errors' <<<"$cur" >&2
    exit 1
  fi
  others='[]'
fi

BODY=$(jq -n --argjson others "$others" --argjson rule "$RULE" '{ rules: ($others + [$rule]) }')

if [[ $DRY -eq 1 ]]; then
  echo "DRY RUN: would PUT /zones/$ZONE_ID/rulesets/phases/http_ratelimit/entrypoint" >&2
  jq . <<<"$BODY"
  exit 0
fi

res=$(cf PUT "/zones/$ZONE_ID/rulesets/phases/http_ratelimit/entrypoint" "$BODY")
if [[ "$(jq -r '.success' <<<"$res")" != "true" ]]; then
  echo "cloudflare: PUT entrypoint failed:" >&2
  jq -c '.errors' <<<"$res" >&2
  exit 1
fi
echo "rate limit rule in place ($REQS req / ${PERIOD}s per IP, block ${TIMEOUT}s):"
jq -r --arg desc "$DESC" '.result.rules[] | select(.description == $desc) | "\(.id)\t\(.expression)"' <<<"$res"
