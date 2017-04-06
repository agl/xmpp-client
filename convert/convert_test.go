package main

import (
	"code.google.com/p/go.crypto/otr"
	"crypto/rand"
	"testing"
)

func TestExport(t *testing.T) {
	var exp, act otr.PrivateKey
	exp.Generate(rand.Reader)
	out := Export(exp)
	act.Import(out)
	if exp.PrivateKey.P.Cmp(act.PrivateKey.P) != 0 {
		t.Errorf("P's don't match")
	}
	if exp.PrivateKey.Q.Cmp(act.PrivateKey.Q) != 0 {
		t.Errorf("Q's don't match")
	}
	if exp.PrivateKey.G.Cmp(act.PrivateKey.G) != 0 {
		t.Errorf("G's don't match")
	}
	if exp.PrivateKey.Y.Cmp(act.PrivateKey.Y) != 0 {
		t.Errorf("Y's don't match")
	}
	if exp.PrivateKey.X.Cmp(act.PrivateKey.X) != 0 {
		t.Errorf("X's don't match")
	}
}
