package main

import (
	"errors"
	"fmt"
	"os"

	"openflux/share"
	"openflux/transport"
)

// buildShare reads an existing exit key; it never creates a new identity just
// to print a QR code for an already-running server.
func buildShare(role, transportType, docURL, keyFile, pskFile, codec string) (share.Config, error) {
	if role != roleExit {
		return share.Config{}, errors.New("--share belongs on the exit node")
	}
	if keyFile == "" {
		return share.Config{}, errors.New("--share needs --exit-key-file")
	}
	if pskFile != "" {
		return share.Config{}, errors.New("--share cannot import PSK-protected nodes into current mobile apps")
	}
	if codec != codecBatched {
		return share.Config{}, errors.New("--share supports the default batched codec only")
	}
	info, err := os.Stat(keyFile)
	if err != nil {
		return share.Config{}, fmt.Errorf("--share needs an existing exit key file: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return share.Config{}, errors.New("--share needs a private regular exit key file (mode 0600)")
	}
	key, created, err := transport.LoadOrCreateStaticKey(keyFile)
	if err != nil {
		return share.Config{}, err
	}
	if created {
		return share.Config{}, errors.New("--share unexpectedly created a new exit key")
	}
	c := share.Config{Transport: transportType, URL: docURL, PeerKey: transport.PublicKeyString(key.Public)}
	return c, c.Validate()
}
