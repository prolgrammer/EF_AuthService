#!/usr/bin/env bash

set -euo pipefail
BASE="${BASE:-http://localhost:8080}"
EMAIL="dev+$(date +%s)@example.com"
PASS="supersecret123"

echo "→ register: $EMAIL"
curl -sS -X POST "$BASE/v1/auth/register" \
  -H 'Content-Type: application/json' \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASS\"}" | jq .

echo "→ login"
LOGIN=$(curl -sS -X POST "$BASE/v1/auth/login" \
  -H 'Content-Type: application/json' \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASS\"}")
echo "$LOGIN" | jq .

ACCESS=$(echo "$LOGIN" | jq -r .access_token)
REFRESH=$(echo "$LOGIN" | jq -r .refresh_token)

echo "→ validate"
curl -sS -X POST "$BASE/v1/auth/validate" \
  -H 'Content-Type: application/json' \
  -d "{\"token\":\"$ACCESS\"}" | jq .

echo "→ refresh"
curl -sS -X POST "$BASE/v1/auth/refresh" \
  -H 'Content-Type: application/json' \
  -d "{\"refresh_token\":\"$REFRESH\"}" | jq .

echo "→ jwks"
curl -sS "$BASE/jwks.json" | jq '.keys[0] | {kty,kid,alg,use}'

echo "✅ smoke passed"
