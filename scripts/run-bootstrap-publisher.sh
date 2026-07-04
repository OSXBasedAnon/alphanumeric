#!/bin/sh
set -eu

REPO_DIR=/Users/satoshi/code/alphanumeric
DATA_DIR="${ALPHANUMERIC_PUBLISHER_DATA_DIR:-/Users/satoshi/.local/share/alphanumeric/publisher}"

mkdir -p "$DATA_DIR"
cd "$DATA_DIR"

TOKEN_FILE=/Users/satoshi/.config/alphanumeric/publisher.txt
if [ ! -s "$TOKEN_FILE" ]; then
    TOKEN_FILE=/Users/satoshi/Documents/publisher.txt
fi

TOKEN="$(tr -d '\r\n' < "$TOKEN_FILE")"

export ALPHANUMERIC_BOOTSTRAP_PUBLISH_TOKEN="$TOKEN"
export ALPHANUMERIC_BIND_IP="${ALPHANUMERIC_BIND_IP:-0.0.0.0}"
export ALPHANUMERIC_PORT="${ALPHANUMERIC_PORT:-7367}"
export ALPHANUMERIC_STATS_ENABLED="${ALPHANUMERIC_STATS_ENABLED:-true}"
export ALPHANUMERIC_STATS_PORT="${ALPHANUMERIC_STATS_PORT:-8787}"
export ALPHANUMERIC_DISCOVERY_BASES="${ALPHANUMERIC_DISCOVERY_BASES:-https://alphanumeric.blue}"
export ALPHANUMERIC_DB_PATH="${ALPHANUMERIC_DB_PATH:-$DATA_DIR/blockchain.db}"
export ALPHANUMERIC_PEER_CACHE_PATH="${ALPHANUMERIC_PEER_CACHE_PATH:-$DATA_DIR/peers.json}"
export ALPHANUMERIC_DISABLE_PUBLIC_ANNOUNCE="${ALPHANUMERIC_DISABLE_PUBLIC_ANNOUNCE:-true}"
export ALPHANUMERIC_HEADLESS=true

exec "$REPO_DIR/target/release/alphanumeric"
