# Secret Drop

A minimal web service for sharing secrets over HTTPS via Cloudflare Tunnel.

An authenticated user pastes text into a form, encrypts it in the browser with a password, and the service stores only the ciphertext. Share links require Basic Auth, and opening a secret also requires the encryption password (decrypted in the browser).

## Features

- Basic Auth for create and read links
- Browser-side encryption/decryption with Web Crypto (no npm)
- Encrypted files on disk (`AES-256-GCM` + `PBKDF2-SHA256`)
- Temporary public HTTPS URL through Cloudflare quick tunnel
- Go CLI utility to decrypt stored files

## Requirements

- Docker
- Docker Compose

## Run

```bash
chmod +x start.sh
./start.sh
```

The script creates `.env` from `.env.example` if needed, starts the stack, and prints the temporary public URL when available.

You can also start manually:

```bash
cp .env.example .env
nano .env
mkdir -p secrets
docker compose up -d --build
docker compose logs -f cloudflared
```

Edit `.env` and set a strong `BASIC_PASS` before use.

## How sharing works

- `push`: open `/`, authenticate with Basic Auth, enter a secret and an encryption password
- the browser encrypts the secret before upload; the server stores only ciphertext
- `pull`: open `/s/<filename>.enc` with Basic Auth, then enter the encryption password in the page
- decryption happens in the browser; the encryption password is not sent to the server

Encrypted JSON is also available at `/s/<filename>.enc/raw` (still behind Basic Auth).

## Decrypt CLI

```bash
docker compose run --rm decrypt
```

The utility lists encrypted files in `./secrets`, asks which one to decrypt, prompts for the password, and prints plaintext to stdout.

## Secret storage

Encrypted secrets are stored on the host in:

```text
./secrets/*.enc
```

Files remain after the containers are stopped, removed, or restarted.

## Stop

```bash
docker compose down
```
