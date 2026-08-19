# Secret Drop

Минимальный веб-сервис: пользователь проходит Basic Auth, вставляет текст, сервис сохраняет его как отдельный `.txt` файл на диск.

Нет API/URL для чтения сохраненных секретов через веб.

## Запуск

```bash
cp .env.example .env
nano .env
mkdir -p secrets
docker compose up -d --build
```

Открыть локально:

```text
http://127.0.0.1:8080
```

Для доступа из интернета поставьте Caddy/nginx/Traefik перед `127.0.0.1:8080` и используйте HTTPS. Basic Auth без HTTPS не защищает пароль от перехвата.

## Где лежат секреты

На хосте:

```text
./secrets/*.txt
```

Посмотреть:

```bash
ls -la secrets/
cat secrets/<filename>.txt
```

## Остановка

```bash
docker compose down
```

Файлы в `./secrets` сохраняются после удаления/перезапуска контейнера.
