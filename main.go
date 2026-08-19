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
    .box { padding: 12px; background: #f6f6f6; margin-bottom: 16px; word-break: break-all; }
    .muted { color: #555; }
  </style>
</head>
<body>
  <h2>Secret Drop</h2>
  {{if .Message}}<div class="ok"><strong>{{.Message}}</strong></div>{{end}}
  {{if .SecretURL}}
  <div class="box">
    <div><strong>Share link:</strong></div>
    <div><a href="{{.SecretURL}}">{{.SecretURL}}</a></div>
    <div class="muted">Anyone with this link can open the secret.</div>
  </div>
  {{end}}
  {{if .Secret}}
  <div class="box">
    <div><strong>Secret:</strong></div>
    <p><a href="{{.RawURL}}">Open raw text</a></p>
    <textarea readonly>{{.Secret}}</textarea>
  </div>
  <p><a href="/">Back</a></p>
  {{else}}
  <form method="post" action="/">
    <textarea name="secret" autofocus required></textarea><br>
    <button type="submit">Save</button>
  </form>
  {{end}}
</body>
</html>`))

type pageData struct {
    Message   string
    SecretURL string
    Secret    string
    RawURL    string
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
            secretURL := buildExternalURL(r, "/s/"+filename)
            if err := page.Execute(w, pageData{
                Message:   "Saved.",
                SecretURL: secretURL,
            }); err != nil {
                log.Printf("template error: %v", err)
            }
        default:
            w.Header().Set("Allow", "GET, POST")
            http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
        }
    })
    mux.HandleFunc("/s/", func(w http.ResponseWriter, r *http.Request) {
        name, raw, ok := parseSecretPath(r.URL.Path)
        if !ok {
            http.NotFound(w, r)
            return
        }
        if r.Method != http.MethodGet {
            w.Header().Set("Allow", "GET")
            http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
            return
        }

        secret, err := readSecret(dataDir, name)
        if err != nil {
            if os.IsNotExist(err) {
                http.NotFound(w, r)
                return
            }
            log.Printf("read error: %v", err)
            http.Error(w, "read failed", http.StatusInternalServerError)
            return
        }

        if raw {
            w.Header().Set("Content-Type", "text/plain; charset=utf-8")
            _, _ = w.Write(secret)
            return
        }

        if err := page.Execute(w, pageData{
            Secret: string(secret),
            RawURL: "/s/" + name + "/raw",
        }); err != nil {
            log.Printf("template error: %v", err)
        }
    })

    handler := authForWriteOnly(user, pass, securityHeaders(mux))

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

    return name, nil
}

func readSecret(dir, name string) ([]byte, error) {
    if !isValidSecretName(name) {
        return nil, os.ErrNotExist
    }
    return os.ReadFile(filepath.Join(dir, name))
}

func parseSecretPath(path string) (name string, raw bool, ok bool) {
    if !strings.HasPrefix(path, "/s/") {
        return "", false, false
    }

    name = strings.TrimPrefix(path, "/s/")
    if strings.HasSuffix(name, "/raw") {
        raw = true
        name = strings.TrimSuffix(name, "/raw")
    }

    if !isValidSecretName(name) {
        return "", false, false
    }
    return name, raw, true
}

func isValidSecretName(name string) bool {
    if name == "" || name != filepath.Base(name) {
        return false
    }
    return strings.HasSuffix(name, ".txt")
}

func authForWriteOnly(username, password string, next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if strings.HasPrefix(r.URL.Path, "/s/") {
            next.ServeHTTP(w, r)
            return
        }

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

func buildExternalURL(r *http.Request, path string) string {
    scheme := "http"
    if forwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")); forwarded != "" {
        scheme = strings.Split(forwarded, ",")[0]
    } else if r.TLS != nil {
        scheme = "https"
    }
    return scheme + "://" + r.Host + path
}

func getenv(name, fallback string) string {
    if value := os.Getenv(name); value != "" {
        return value
    }
    return fallback
}

