package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"secret-drop/internal/secretcrypto"
	"secret-drop/internal/secretfile"
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
    textarea, input[type=password], input[type=text], select { width: 100%; box-sizing: border-box; font-size: 16px; margin-top: 8px; }
    textarea { height: 250px; font-family: monospace; }
    button { margin-top: 12px; padding: 10px 20px; font-size: 16px; }
    label { display: block; margin-top: 12px; }
    .check { display: flex; align-items: center; gap: 8px; margin-top: 12px; }
    .check input { width: auto; margin: 0; }
    .ok { padding: 12px; background: #eee; margin-bottom: 16px; }
    .err { padding: 12px; background: #fdecea; color: #611a15; margin-bottom: 16px; }
    .box { padding: 12px; background: #f6f6f6; margin-bottom: 16px; word-break: break-all; }
    .muted { color: #555; }
    .hidden { display: none; }
  </style>
</head>
<body>
  <h2>Secret Drop</h2>
  {{if .Message}}<div class="ok"><strong>{{.Message}}</strong></div>{{end}}
  {{if .SecretURL}}
  <div class="box">
    <div><strong>Share link:</strong></div>
    <div><a href="{{.SecretURL}}">{{.SecretURL}}</a></div>
    <div class="muted">Basic Auth is required. Recipients also need the encryption password.</div>
    {{if .MetaLine}}<div class="muted">{{.MetaLine}}</div>{{end}}
  </div>
  {{end}}

  {{if .Ciphertext}}
  <div class="box">
    <div><strong>Encrypted secret</strong></div>
    <div class="muted">Enter the encryption password to decrypt in the browser. The password is not sent to the server.</div>
    {{if .MetaLine}}<div class="muted">{{.MetaLine}}</div>{{end}}
    <label>Password
      <input id="view-password" type="password" autocomplete="off" required>
    </label>
    <button type="button" id="decrypt-btn">Decrypt</button>
    <div id="view-error" class="err hidden"></div>
    <div id="view-info" class="ok hidden"></div>
    <textarea id="view-plain" class="hidden" readonly></textarea>
  </div>
  <p><a href="/">Back</a></p>
  <textarea id="enc-payload" class="hidden" readonly>{{.Ciphertext}}</textarea>
  <script>
  (function () {
    const enc = new TextEncoder();
    const dec = new TextDecoder();
    const filename = {{printf "%q" .Filename}};
    const once = {{.Once}};

    function b64ToBytes(b64) {
      const bin = atob(b64);
      const out = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
      return out;
    }

    async function deriveKey(password, salt, iterations) {
      const material = await crypto.subtle.importKey(
        "raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]
      );
      return crypto.subtle.deriveKey(
        { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
        material,
        { name: "AES-GCM", length: 256 },
        false,
        ["decrypt"]
      );
    }

    async function decryptPayload(payload, password) {
      if (!payload || payload.v !== 1 || payload.kdf !== "PBKDF2-SHA256") {
        throw new Error("unsupported payload");
      }
      const salt = b64ToBytes(payload.salt);
      const nonce = b64ToBytes(payload.nonce);
      const ct = b64ToBytes(payload.ct);
      const key = await deriveKey(password, salt, Number(payload.iter));
      const plainBuf = await crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce }, key, ct);
      return dec.decode(plainBuf);
    }

    const payload = JSON.parse(document.getElementById("enc-payload").value);
    const btn = document.getElementById("decrypt-btn");
    const passEl = document.getElementById("view-password");
    const errEl = document.getElementById("view-error");
    const infoEl = document.getElementById("view-info");
    const outEl = document.getElementById("view-plain");

    async function markConsumed() {
      if (!once) return;
      const resp = await fetch("/s/" + encodeURIComponent(filename) + "/consumed", {
        method: "POST",
        credentials: "same-origin"
      });
      if (resp.ok) {
        infoEl.textContent = "One-time secret deleted from the server.";
        infoEl.classList.remove("hidden");
      }
    }

    async function runDecrypt() {
      errEl.classList.add("hidden");
      infoEl.classList.add("hidden");
      outEl.classList.add("hidden");
      outEl.value = "";
      try {
        const plain = await decryptPayload(payload, passEl.value);
        outEl.value = plain;
        outEl.classList.remove("hidden");
        await markConsumed();
      } catch (e) {
        errEl.textContent = "Wrong password or corrupted payload.";
        errEl.classList.remove("hidden");
      }
    }

    btn.addEventListener("click", runDecrypt);
    passEl.addEventListener("keydown", function (e) {
      if (e.key === "Enter") runDecrypt();
    });
  })();
  </script>
  {{else}}
  <form id="create-form">
    <label>Name (optional)
      <input id="secret-name" type="text" maxlength="40" autocomplete="off" placeholder="e.g. vpn-token">
    </label>
    <label>Secret
      <textarea id="secret" autofocus required></textarea>
    </label>
    <label>Encryption password
      <input id="password" type="password" autocomplete="new-password" required>
    </label>
    <label>Confirm password
      <input id="password2" type="password" autocomplete="new-password" required>
    </label>
    <label>Expires
      <select id="ttl">
        <option value="0">Never</option>
        <option value="3600">1 hour</option>
        <option value="21600">6 hours</option>
        <option value="86400" selected>24 hours</option>
        <option value="604800">7 days</option>
      </select>
    </label>
    <label class="check">
      <input id="once" type="checkbox" checked>
      <span>Delete after first successful decrypt (one-time link)</span>
    </label>
    <div id="create-error" class="err hidden"></div>
    <button type="submit" id="save-btn">Save</button>
  </form>
  <script>
  (function () {
    const enc = new TextEncoder();

    function bytesToB64(bytes) {
      let s = "";
      for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
      return btoa(s);
    }

    async function deriveKey(password, salt, iterations) {
      const material = await crypto.subtle.importKey(
        "raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]
      );
      return crypto.subtle.deriveKey(
        { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
        material,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt"]
      );
    }

    async function encryptSecret(plaintext, password) {
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const nonce = crypto.getRandomValues(new Uint8Array(12));
      const iterations = 210000;
      const key = await deriveKey(password, salt, iterations);
      const ctBuf = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: nonce },
        key,
        enc.encode(plaintext)
      );
      return {
        v: 1,
        kdf: "PBKDF2-SHA256",
        iter: iterations,
        salt: bytesToB64(salt),
        nonce: bytesToB64(nonce),
        ct: bytesToB64(new Uint8Array(ctBuf))
      };
    }

    const form = document.getElementById("create-form");
    const errEl = document.getElementById("create-error");
    const saveBtn = document.getElementById("save-btn");

    form.addEventListener("submit", async function (e) {
      e.preventDefault();
      errEl.classList.add("hidden");
      const secret = document.getElementById("secret").value;
      const password = document.getElementById("password").value;
      const password2 = document.getElementById("password2").value;
      if (!secret.trim()) {
        errEl.textContent = "Secret is empty.";
        errEl.classList.remove("hidden");
        return;
      }
      if (!password) {
        errEl.textContent = "Password is required.";
        errEl.classList.remove("hidden");
        return;
      }
      if (password !== password2) {
        errEl.textContent = "Passwords do not match.";
        errEl.classList.remove("hidden");
        return;
      }

      saveBtn.disabled = true;
      try {
        const payload = await encryptSecret(secret, password);
        const name = document.getElementById("secret-name").value.trim();
        const once = document.getElementById("once").checked;
        const ttlSeconds = Number(document.getElementById("ttl").value);
        const resp = await fetch("/", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            name: name,
            once: once,
            ttl_seconds: ttlSeconds,
            payload: payload
          }),
          credentials: "same-origin"
        });
        if (!resp.ok) {
          throw new Error("save failed");
        }
        const html = await resp.text();
        document.open();
        document.write(html);
        document.close();
      } catch (err) {
        errEl.textContent = "Failed to encrypt or save secret.";
        errEl.classList.remove("hidden");
        saveBtn.disabled = false;
      }
    });
  })();
  </script>
  {{end}}
</body>
</html>`))

type pageData struct {
	Message    string
	SecretURL  string
	Ciphertext string
	Filename   string
	Once       bool
	MetaLine   string
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

	go expireLoop(dataDir)

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
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "invalid request", http.StatusBadRequest)
				return
			}

			var req struct {
				Name       string          `json:"name"`
				Once       bool            `json:"once"`
				TTLSeconds int64           `json:"ttl_seconds"`
				Payload    json.RawMessage `json:"payload"`
			}
			if err := json.Unmarshal(body, &req); err != nil || !secretcrypto.IsPayload(req.Payload) {
				http.Error(w, "invalid encrypted payload", http.StatusBadRequest)
				return
			}
			if req.TTLSeconds < 0 {
				http.Error(w, "invalid ttl", http.StatusBadRequest)
				return
			}

			var expiresAt *time.Time
			if req.TTLSeconds > 0 {
				t := time.Now().UTC().Add(time.Duration(req.TTLSeconds) * time.Second)
				expiresAt = &t
			}

			wrapped, err := secretfile.Wrap(req.Payload, req.Once, expiresAt)
			if err != nil {
				http.Error(w, "invalid encrypted payload", http.StatusBadRequest)
				return
			}

			filename, err := saveSecret(dataDir, wrapped, req.Name)
			if err != nil {
				log.Printf("save error: %v", err)
				http.Error(w, "save failed", http.StatusInternalServerError)
				return
			}

			log.Printf("saved encrypted secret: %s", filename)
			secretURL := buildExternalURL(r, "/s/"+filename)
			if err := page.Execute(w, pageData{
				Message:   "Saved.",
				SecretURL: secretURL,
				MetaLine:  formatMeta(req.Once, expiresAt),
			}); err != nil {
				log.Printf("template error: %v", err)
			}
		default:
			w.Header().Set("Allow", "GET, POST")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/s/", func(w http.ResponseWriter, r *http.Request) {
		name, action, ok := parseSecretPath(r.URL.Path)
		if !ok {
			http.NotFound(w, r)
			return
		}

		path := filepath.Join(dataDir, name)

		switch action {
		case "consumed":
			if r.Method != http.MethodPost {
				w.Header().Set("Allow", "POST")
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			blob, err := os.ReadFile(path)
			if err != nil {
				if os.IsNotExist(err) {
					http.NotFound(w, r)
					return
				}
				http.Error(w, "read failed", http.StatusInternalServerError)
				return
			}
			env, err := secretfile.Open(blob)
			if err != nil {
				http.Error(w, "invalid secret", http.StatusInternalServerError)
				return
			}
			if !env.Once {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			if err := secretfile.DeleteIfExists(path); err != nil {
				http.Error(w, "delete failed", http.StatusInternalServerError)
				return
			}
			log.Printf("consumed one-time secret: %s", name)
			w.WriteHeader(http.StatusNoContent)
			return
		}

		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		blob, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				http.NotFound(w, r)
				return
			}
			log.Printf("read error: %v", err)
			http.Error(w, "read failed", http.StatusInternalServerError)
			return
		}

		env, err := secretfile.Open(blob)
		if err != nil {
			http.Error(w, "invalid encrypted payload", http.StatusInternalServerError)
			return
		}
		if env.Expired(time.Now().UTC()) {
			_ = secretfile.DeleteIfExists(path)
			http.NotFound(w, r)
			return
		}

		if action == "raw" {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			_, _ = w.Write(env.Payload)
			return
		}

		if err := page.Execute(w, pageData{
			Ciphertext: string(env.Payload),
			Filename:   name,
			Once:       env.Once,
			MetaLine:   formatMeta(env.Once, env.ExpiresAt),
		}); err != nil {
			log.Printf("template error: %v", err)
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

func expireLoop(dir string) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for {
		purgeExpired(dir)
		<-ticker.C
	}
}

func purgeExpired(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	now := time.Now().UTC()
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".enc") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		blob, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		env, err := secretfile.Open(blob)
		if err != nil {
			continue
		}
		if env.Expired(now) {
			if err := secretfile.DeleteIfExists(path); err == nil {
				log.Printf("expired secret deleted: %s", entry.Name())
			}
		}
	}
}

func formatMeta(once bool, expiresAt *time.Time) string {
	parts := make([]string, 0, 2)
	if once {
		parts = append(parts, "One-time link (deleted after first successful decrypt).")
	} else {
		parts = append(parts, "Reusable link.")
	}
	if expiresAt == nil {
		parts = append(parts, "No expiry.")
	} else {
		parts = append(parts, "Expires at "+expiresAt.UTC().Format(time.RFC3339)+".")
	}
	return strings.Join(parts, " ")
}

func saveSecret(dir string, data []byte, label string) (string, error) {
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return "", err
	}

	name := time.Now().UTC().Format("20060102-150405") + "-" + hex.EncodeToString(id)
	if safe := sanitizeSecretLabel(label); safe != "" {
		name += "-" + safe
	}
	name += ".enc"
	path := filepath.Join(dir, name)

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return "", err
	}
	defer f.Close()

	if _, err := f.Write(data); err != nil {
		return "", err
	}
	if err := f.Sync(); err != nil {
		return "", err
	}
	return name, nil
}

func sanitizeSecretLabel(label string) string {
	label = strings.TrimSpace(label)
	if label == "" {
		return ""
	}

	var b strings.Builder
	lastDash := false
	for _, r := range label {
		switch {
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			b.WriteRune(unicode.ToLower(r))
			lastDash = false
		case r == '-' || r == '_' || unicode.IsSpace(r):
			if b.Len() == 0 || lastDash {
				continue
			}
			b.WriteByte('-')
			lastDash = true
		}
		if b.Len() >= 40 {
			break
		}
	}

	return strings.Trim(b.String(), "-_")
}

func parseSecretPath(path string) (name string, action string, ok bool) {
	if !strings.HasPrefix(path, "/s/") {
		return "", "", false
	}

	rest := strings.TrimPrefix(path, "/s/")
	switch {
	case strings.HasSuffix(rest, "/raw"):
		action = "raw"
		name = strings.TrimSuffix(rest, "/raw")
	case strings.HasSuffix(rest, "/consumed"):
		action = "consumed"
		name = strings.TrimSuffix(rest, "/consumed")
	default:
		name = rest
	}

	if !isValidSecretName(name) {
		return "", "", false
	}
	return name, action, true
}

func isValidSecretName(name string) bool {
	if name == "" || name != filepath.Base(name) {
		return false
	}
	return strings.HasSuffix(name, ".enc")
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
