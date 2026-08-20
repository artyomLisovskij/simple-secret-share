package secretfile

import (
	"encoding/json"
	"errors"
	"os"
	"time"

	"secret-drop/internal/secretcrypto"
)

const EnvelopeVersion = 1

var (
	ErrInvalidEnvelope = errors.New("invalid secret envelope")
	ErrExpired         = errors.New("secret expired")
)

type Envelope struct {
	Version   int             `json:"v"`
	Once      bool            `json:"once"`
	ExpiresAt *time.Time      `json:"expires_at"`
	Payload   json.RawMessage `json:"payload"`
}

func Wrap(payload []byte, once bool, expiresAt *time.Time) ([]byte, error) {
	if !secretcrypto.IsPayload(payload) {
		return nil, ErrInvalidEnvelope
	}
	env := Envelope{
		Version:   EnvelopeVersion,
		Once:      once,
		ExpiresAt: expiresAt,
		Payload:   json.RawMessage(append([]byte(nil), payload...)),
	}
	return json.Marshal(env)
}

func Open(blob []byte) (Envelope, error) {
	if secretcrypto.IsPayload(blob) {
		return Envelope{
			Version: EnvelopeVersion,
			Once:    false,
			Payload: json.RawMessage(append([]byte(nil), blob...)),
		}, nil
	}

	var env Envelope
	if err := json.Unmarshal(blob, &env); err != nil {
		return Envelope{}, ErrInvalidEnvelope
	}
	if env.Version != EnvelopeVersion || !secretcrypto.IsPayload(env.Payload) {
		return Envelope{}, ErrInvalidEnvelope
	}
	return env, nil
}

func (e Envelope) Expired(now time.Time) bool {
	return e.ExpiresAt != nil && !e.ExpiresAt.After(now)
}

func DeleteIfExists(path string) error {
	err := os.Remove(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
