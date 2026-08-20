#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required" >&2
  exit 1
fi

if ! docker compose version >/dev/null 2>&1; then
  echo "docker compose is required" >&2
  exit 1
fi

if [[ ! -f .env ]]; then
  if [[ -f .env.example ]]; then
    cp .env.example .env
    echo "Created .env from .env.example — edit BASIC_USER and BASIC_PASS before sharing secrets."
  else
    echo ".env is missing" >&2
    exit 1
  fi
fi

mkdir -p secrets

docker compose up -d --build

echo
echo "Waiting for Cloudflare quick tunnel URL..."

url=""
for _ in $(seq 1 60); do
  url="$(docker compose logs cloudflared 2>/dev/null | grep -Eo 'https://[a-zA-Z0-9.-]+\.trycloudflare\.com' | tail -n 1 || true)"
  if [[ -n "$url" ]]; then
    break
  fi
  sleep 1
done

if [[ -n "$url" ]]; then
  echo "Public URL: $url"
else
  echo "Tunnel URL not found yet. Check logs:"
  echo "  docker compose logs -f cloudflared"
fi

echo
echo "Useful commands:"
echo "  docker compose logs -f cloudflared"
echo "  docker compose run --rm decrypt"
echo "  docker compose down"
