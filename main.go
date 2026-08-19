package main

import (
    "crypto/rand"
    "crypto/subtle"
    "encoding/hex"
    "html/template"
    "log"
    "net/http"
    "os"
    "path/filepath"
    "strings"
    "time"
)

const maxSecretSize = 1024 * 1024 // 1 MB

var page = template.Must(template.New("page").Parse(`<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Secret Drop</title>
  <style>
    body { font-family: sans-serif; max-width: 700px; margin: 60px auto; padding: 0 20px; }
    textarea { width: 100%; height: 250px; box-sizing: border-box; font-family: monospace; font-size: 16px; }
    button { margin-top: 12px; padding: 10px 20px; font-size: 16px; }
    .ok { padding: 12px; background: #eee; margin-bottom: 16px; }
  </style>
</head>
<body>
  <h2>Secret Drop</h2>
  {{if .Message}}<div class="ok"><strong>{{.Message}}</strong></div>{{end}}
  <form method="post" action="/">
    <textarea name="secret" autofocus required></textarea><br>
    <button type="submit">Save</button>
  </form>
</body>
</html>`))

type pageData struct {
    Message string
}

func main() {
    addr := getenv("LISTEN", "0.0.0.0:8080")
    dataDir := getenv("DATA_DIR", "/data")
    user := os.Getenv("BASIC_USER")
    pass := os.Getenv("BASIC_PASS")

    if user == "" || pass == "" {
        log.Fatal("BASIC_USER and BASIC_PASS must be set")
    }

    if err := os.MkdirAll(dataDir, 0700); err != nil {
        log.Fatal(err)
    }

    mux := http.NewServeMux()
    mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        if r.URL.Path != "/" {
            http.NotFound(w, r)
            return
        }

        switch r.Method {
        case http.MethodGet:
            if err := page.Execute(w, pageData{}); err != nil {
                log.Printf("template error: %v", err)
            }
        case http.MethodPost:
            r.Body = http.MaxBytesReader(w, r.Body, maxSecretSize)
            if err := r.ParseForm(); err != nil {
                http.Error(w, "invalid request", http.StatusBadRequest)
                return
            }

            secret := r.FormValue("secret")
            if strings.TrimSpace(secret) == "" {
                http.Error(w, "empty secret", http.StatusBadRequest)
                return
            }

            filename, err := saveSecret(dataDir, []byte(secret))
            if err != nil {
                log.Printf("save error: %v", err)
                http.Error(w, "save failed", http.StatusInternalServerError)
                return
            }

            log.Printf("saved secret: %s", filename)
            if err := page.Execute(w, pageData{Message: "Saved."}); err != nil {
                log.Printf("template error: %v", err)
            }
        default:
            w.Header().Set("Allow", "GET, POST")
            http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
        }
    })

    handler := basicAuth(user, pass, securityHeaders(mux))

    server := &http.Server{
        Addr:              addr,
        Handler:           handler,
        ReadHeaderTimeout: 5 * time.Second,
        ReadTimeout:       10 * time.Second,
        WriteTimeout:      10 * time.Second,
        IdleTimeout:       30 * time.Second,
    }

    log.Printf("listening on %s", addr)
    log.Fatal(server.ListenAndServe())
}

func saveSecret(dir string, data []byte) (string, error) {
    id := make([]byte, 16)
    if _, err := rand.Read(id); err != nil {
        return "", err
    }

    name := time.Now().UTC().Format("20060102-150405") + "-" + hex.EncodeToString(id) + ".txt"
    path := filepath.Join(dir, name)

    f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
    if err != nil {
        return "", err
    }

    if _, err := f.Write(data); err != nil {
        _ = f.Close()
        return "", err
    }
    if err := f.Sync(); err != nil {
        _ = f.Close()
        return "", err
    }
    if err := f.Close(); err != nil {
        return "", err
    }

    return path, nil
}

func basicAuth(username, password string, next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        user, pass, ok := r.BasicAuth()

        userOK := subtle.ConstantTimeCompare([]byte(user), []byte(username)) == 1
        passOK := subtle.ConstantTimeCompare([]byte(pass), []byte(password)) == 1

        if !ok || !userOK || !passOK {
            w.Header().Set("WWW-Authenticate", `Basic realm="Secret Drop"`)
            http.Error(w, "Unauthorized", http.StatusUnauthorized)
            return
        }

        next.ServeHTTP(w, r)
    })
}

func securityHeaders(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Cache-Control", "no-store")
        w.Header().Set("Pragma", "no-cache")
        w.Header().Set("X-Content-Type-Options", "nosniff")
        w.Header().Set("X-Frame-Options", "DENY")
        w.Header().Set("Referrer-Policy", "no-referrer")
        next.ServeHTTP(w, r)
    })
}

func getenv(name, fallback string) string {
    if value := os.Getenv(name); value != "" {
        return value
    }
    return fallback
}

