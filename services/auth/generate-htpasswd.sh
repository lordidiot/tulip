#!/usr/bin/env bash
# generate-htpasswd.sh
# Usage: ./generate-htpasswd.sh [username] [password]

set -e
cd "$(dirname "$0")"

USER="${1:-}"
PASS="${2:-}"

if [ -z "$USER" ]; then
  read -rp "Username: " USER
fi

if [ -z "$PASS" ]; then
  read -srp "Password: " PASS
  echo
fi

docker run --rm httpd:2-alpine htpasswd -nbB "$USER" "$PASS" > htpasswd
echo "htpasswd file generated for user '$USER'"
