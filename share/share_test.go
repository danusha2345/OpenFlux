package share

import (
	"encoding/base64"
	"strings"
	"testing"
)

func sample() Config {
	return Config{
		Transport: "mailru",
		URL:       "https://cloud.mail.ru/public/abc/def",
		PeerKey:   base64.StdEncoding.EncodeToString(make([]byte, 32)),
	}
}

func TestRoundTripAndQR(t *testing.T) {
	want := sample()
	link, err := Encode(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(link)
	if err != nil || got != want {
		t.Fatalf("decode=%+v err=%v", got, err)
	}
	text, err := Terminal(link)
	if err != nil || strings.Count(text, "\n") < 10 {
		t.Fatalf("terminal QR: %v", err)
	}
}

func TestRejectsInvalidLinks(t *testing.T) {
	for _, change := range []func(*Config){
		func(c *Config) { c.Transport = "oneme" },
		func(c *Config) { c.URL = "" },
		func(c *Config) { c.URL = "http://#" },
		func(c *Config) { c.PeerKey = "bad" },
	} {
		c := sample()
		change(&c)
		if _, err := Encode(c); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	if _, err := Decode("openflux://v1/foo"); err == nil {
		t.Fatal("accepted incompatible upstream link")
	}
	if _, err := Decode(Prefix + strings.Repeat("A", 4097)); err == nil {
		t.Fatal("accepted oversized QR link")
	}
}
