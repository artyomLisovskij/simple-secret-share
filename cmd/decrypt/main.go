package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/term"

	"secret-drop/internal/secretcrypto"
	"secret-drop/internal/secretfile"
)

func main() {
	dir := getenv("DATA_DIR", "/data")
	files, err := listEncFiles(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "list error: %v\n", err)
		os.Exit(1)
	}
	if len(files) == 0 {
		fmt.Fprintf(os.Stderr, "no encrypted secrets in %s\n", dir)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "Encrypted secrets in %s:\n", dir)
	for i, name := range files {
		fmt.Fprintf(os.Stderr, "  %d) %s\n", i+1, name)
	}

	fmt.Fprint(os.Stderr, "Select number: ")
	choice, err := readLine()
	if err != nil {
		fmt.Fprintf(os.Stderr, "input error: %v\n", err)
		os.Exit(1)
	}
	idx, err := strconv.Atoi(strings.TrimSpace(choice))
	if err != nil || idx < 1 || idx > len(files) {
		fmt.Fprintln(os.Stderr, "invalid selection")
		os.Exit(1)
	}

	path := filepath.Join(dir, files[idx-1])
	blob, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read error: %v\n", err)
		os.Exit(1)
	}

	env, err := secretfile.Open(blob)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open error: %v\n", err)
		os.Exit(1)
	}
	if env.Expired(time.Now().UTC()) {
		_ = secretfile.DeleteIfExists(path)
		fmt.Fprintln(os.Stderr, "secret expired")
		os.Exit(1)
	}

	fmt.Fprint(os.Stderr, "Password: ")
	passBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "password error: %v\n", err)
		os.Exit(1)
	}

	plain, err := secretcrypto.Decrypt(env.Payload, string(passBytes))
	if err != nil {
		fmt.Fprintf(os.Stderr, "decrypt error: %v\n", err)
		os.Exit(1)
	}

	if env.Once {
		if err := secretfile.DeleteIfExists(path); err != nil {
			fmt.Fprintf(os.Stderr, "delete error: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintln(os.Stderr, "One-time secret deleted from disk.")
	}

	_, _ = os.Stdout.Write(plain)
	if len(plain) == 0 || plain[len(plain)-1] != '\n' {
		fmt.Fprintln(os.Stdout)
	}
}

func listEncFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	var files []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasSuffix(name, ".enc") {
			files = append(files, name)
		}
	}
	sort.Strings(files)
	return files, nil
}

func readLine() (string, error) {
	reader := bufio.NewReader(os.Stdin)
	return reader.ReadString('\n')
}

func getenv(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
