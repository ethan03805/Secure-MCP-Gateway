package pipeline

import (
	"context"
	"testing"
)

func TestNoEgressAttachesNoNetwork(t *testing.T) {
	a, err := NoEgress{}.Attach(context.Background(), ServerSpec{Alias: "x"}, "i1")
	if err != nil {
		t.Fatal(err)
	}
	if a.Network != NetworkNone || len(a.Env) != 0 || a.Release != nil {
		t.Fatalf("default attachment = %+v, want network none and nothing else", a)
	}
}
