// Package share encodes a Noise client configuration for QR import on mobile.
package share

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	qrcode "github.com/skip2/go-qrcode"

	"openflux/transport"
)

// The explicit Noise version keeps this fork's links distinct from upstream's
// AES/session links, which cannot be used by these clients.
const Prefix = "openflux://noise-v1/"

type Config struct {
	Transport string `json:"transport"`
	URL       string `json:"url"`
	PeerKey   string `json:"peerKey"`
}

func (c Config) Validate() error {
	switch c.Transport {
	case "yandex", "vyandex", "cupsonline", "mailru":
	default:
		return fmt.Errorf("share: unsupported transport %q", c.Transport)
	}
	if strings.TrimSpace(c.URL) != c.URL || c.URL == "" || c.URL == "http://#" || len(c.URL) > 2048 {
		return errors.New("share: invalid or missing document/room URL")
	}
	if _, err := transport.ParsePublicKey(c.PeerKey); err != nil {
		return fmt.Errorf("share: %w", err)
	}
	return nil
}

func Encode(c Config) (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	return Prefix + base64.RawURLEncoding.EncodeToString(raw), nil
}

func Decode(link string) (Config, error) {
	if !strings.HasPrefix(link, Prefix) {
		return Config{}, errors.New("share: unsupported link format")
	}
	encoded := strings.TrimPrefix(link, Prefix)
	if len(encoded) > 4096 {
		return Config{}, errors.New("share: link too large")
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return Config{}, fmt.Errorf("share: bad link encoding: %w", err)
	}
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return Config{}, fmt.Errorf("share: bad link payload: %w", err)
	}
	if err := c.Validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}

func Terminal(link string) (string, error) {
	if _, err := Decode(link); err != nil {
		return "", err
	}
	qr, err := qrcode.New(link, qrcode.Medium)
	if err != nil {
		return "", err
	}
	return qr.ToSmallString(false), nil
}
