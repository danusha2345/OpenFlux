//go:build linux && !android

package netbind

import "testing"

func TestDefaultDevice(t *testing.T) {
	for _, tc := range []struct{ data, want string }{
		{`[{"dev":"eth0","metric":600},{"dev":"wlan0","metric":100}]`, "wlan0"},
		{`[{"type":"blackhole"},{"dev":"eth0"}]`, "eth0"},
		{`[]`, ""}, {`invalid`, ""},
	} {
		got, err := defaultDevice([]byte(tc.data))
		if got != tc.want || (err != nil) != (tc.want == "") {
			t.Fatalf("%s: got %q, %v", tc.data, got, err)
		}
	}
}
