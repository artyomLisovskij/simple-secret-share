# Secret Drop

A minimal web service for sharing secrets over HTTPS via Cloudflare Tunnel.

An authenticated user pastes text into a form, encrypts it in the browser with a password, and the service stores only the ciphertext. Share links require Basic Auth, and opening a secret also requires the encryption password (decrypted in the browser).

## Advantages

- No host port publish: the app stays on the Docker network; public access goes only through Cloudflare Tunnel
- Account-less Cloudflare quick tunnel: no Cloudflare account required for a temporary public endpoint
- Automated random `trycloudflare.com` hostname with HTTPS/TLS
- Basic Auth for both creating and opening secrets
- Frontend encryption with the Web Crypto API and no third-party JavaScript libraries
- Push and pull of encrypted secrets over shareable links
- Optional secret name, reflected in the filename and in the share URL
- Optional one-time links and TTL, with reusable/never-expire modes available
- Decryption only in the browser or via the CLI; the encryption password is not sent to the server
- On-disk storage of ciphertext only (`./secrets/*.enc`)

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

- `push`: open `/`, authenticate with Basic Auth, optionally set a name/TTL/one-time mode, enter a secret and an encryption password
- the browser encrypts the secret before upload; the server stores only ciphertext plus link metadata
- if a name is provided, it is appended to the filename (`...-<name>.enc`)
- `pull`: open `/s/<filename>.enc` with Basic Auth, then enter the encryption password in the page
- decryption happens in the browser; the encryption password is not sent to the server
- one-time secrets are deleted after the first successful decrypt; expired secrets are removed automatically

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
