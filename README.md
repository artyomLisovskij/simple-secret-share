# Secret Drop

A minimal web service for receiving secrets: the user authenticates with Basic Auth, pastes text into a form, and the service saves it as a separate `.txt` file on disk.

There is no API or web URL for reading stored secrets back through the application.

## Run

```bash
cp .env.example .env
nano .env
mkdir -p secrets
docker compose up -d --build
```

Open locally:

```text
http://127.0.0.1:8080
```

For Internet access, put Caddy, nginx, or Traefik in front of `127.0.0.1:8080` and use HTTPS. Basic Auth alone does not encrypt credentials in transit.

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
