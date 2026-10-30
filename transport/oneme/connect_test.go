package oneme

import "testing"

func TestLoginWithoutConnectionReturnsError(t *testing.T) {
	c := NewMaxClient()
	if err := c.LoginByToken("test"); err == nil {
		t.Fatal("expected connection error")
	}
}
