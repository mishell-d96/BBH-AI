#!/usr/bin/env bash
# Reusable auth helper for demo.testfire.net (AltoroJ).  Source it:  source altoro.sh
# Speeds up authenticated testing: token is short-lived, so atok re-captures on demand.
#   atok [user] [pass]      -> echo a fresh Authorization token (default jsmith/demo1234)
#   aget <path>             -> GET  https://demo.testfire.net<path> with a fresh token
#   apost <path> <json>     -> POST https://demo.testfire.net<path> with a fresh token + JSON body
# Methodology validation only — intentionally-vulnerable IBM demo, accepted-risk-by-design.
BASE="https://demo.testfire.net"

atok() {
  local u="${1:-jsmith}" p="${2:-demo1234}"
  curl -sk -X POST "$BASE/api/login" -H 'Content-Type: application/json' \
    -d "{\"username\":\"$u\",\"password\":\"$p\"}" | jq -r '.Authorization'
}

aget()  { curl -sk "$BASE$1"  -H "Authorization: $(atok)"; echo; }
apost() { curl -sk -X POST "$BASE$1" -H "Authorization: $(atok)" -H 'Content-Type: application/json' -d "$2"; echo; }

# bal <accountNo>  -> balance field (note: integer-overflowed on this demo; prefer txns for proof)
bal()  { aget "/api/account/$1" | jq -r '.balance'; }
# txns <accountNo> -> last 10 transactions (reliable money-movement proof)
txns() { aget "/api/account/$1/transactions" | jq '.last_10_transactions'; }
