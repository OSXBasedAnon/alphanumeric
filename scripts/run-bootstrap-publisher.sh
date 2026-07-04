#!/bin/sh
set -eu

cd /Users/satoshi/code/alphanumeric

TOKEN_FILE=/Users/satoshi/.config/alphanumeric/publisher.txt
if [ ! -s "$TOKEN_FILE" ]; then
    TOKEN_FILE=/Users/satoshi/Documents/publisher.txt
fi

TOKEN="$(tr -d '\r\n' < "$TOKEN_FILE")"

export ALPHANUMERIC_BOOTSTRAP_PUBLISH_TOKEN="$TOKEN"
export ALPHANUMERIC_BIND_IP="${ALPHANUMERIC_BIND_IP:-0.0.0.0}"
export ALPHANUMERIC_DB_PATH="${ALPHANUMERIC_DB_PATH:-/Users/satoshi/code/alphanumeric/target/release/blockchain.db}"
export ALPHANUMERIC_HEADLESS=true

exec /Users/satoshi/code/alphanumeric/target/release/alphanumeric
