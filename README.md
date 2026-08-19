# Secret Drop

A minimal web service for sharing secrets: an authenticated user pastes text into a form, the service saves it as a separate `.txt` file on disk, and then returns a shareable URL for reading that secret back.

## Run

```bash
cp .env.example .env
nano .env
mkdir -p secrets
docker compose up -d --build
```

Get the temporary Cloudflare Tunnel URL:

```bash
docker compose logs -f cloudflared
```

`cloudflared` will print a temporary `trycloudflare.com` hostname on startup. Open that URL to access the app over HTTPS.

The tunnel is temporary, so the public hostname may change after a restart.

## How sharing works

- `push`: open `/`, authenticate with Basic Auth, and submit a secret
- `pull`: after saving, the app shows a shareable URL like `/s/<filename>.txt`
- anyone with the share link can open that specific secret without Basic Auth

The returned link is based on the incoming request host, so it works correctly behind the temporary Cloudflare Tunnel hostname.

## Secret storage

Secrets are stored on the host in:

```text
./secrets/*.txt
```

To inspect them locally:

```bash
ls -la secrets/
cat secrets/<filename>.txt
```

## Stop

```bash
docker compose down
```

Files in `./secrets` remain on disk after the container is stopped, removed, or restarted.
