package relwe

import (
	"encoding/hex"
	"testing"
)

func TestNTTRoundTrip(t *testing.T) {
	values := make([]int, N)
	for i := range values {
		values[i] = (i*17 + 3) % Q
	}
	got := INTT(NTT(values))
	for i := range values {
		if got[i] != values[i] {
			t.Fatalf("roundtrip mismatch at %d: got %d want %d", i, got[i], values[i])
		}
	}
}

func TestMulMatchesSchoolbook(t *testing.T) {
	var a, b ringPoly
	for i := 0; i < N; i++ {
		a.coeffs[i] = (i*19 + 7) % Q
		b.coeffs[i] = (i*i + 11) % Q
	}
	got := a.mul(b)
	want := schoolbookReference(a, b)
	if got != want {
		t.Fatal("NTT product does not match schoolbook reference")
	}
}

func TestHashDeterministic(t *testing.T) {
	h := NewWithParams(3, 4, 256)
	a := h.Hash("empty tomb")
	b := h.Hash("empty tomb")
	c := h.Hash("Empty tomb")
	if a != b {
		t.Fatal("same input produced different digests")
	}
	if a == c {
		t.Fatal("different input produced same digest in smoke test")
	}
	if len(a) != 64 {
		t.Fatalf("unexpected digest length: %d", len(a))
	}
}

func TestEtaConfiguration(t *testing.T) {
	defaultHash := NewWithParams(3, 4, 256).Hash("eta smoke")
	explicitDefault := NewFromConfig(Config{K: 3, Rounds: 4, OutputBits: 256, Eta: DefaultEta}).Hash("eta smoke")
	eta4 := NewFromConfig(Config{K: 3, Rounds: 4, OutputBits: 256, Eta: 4}).Hash("eta smoke")
	if defaultHash != explicitDefault {
		t.Fatal("explicit default eta changed legacy default behavior")
	}
	if defaultHash == eta4 {
		t.Fatal("changing eta did not affect digest")
	}
}

func TestDefaultRoundsIs32(t *testing.T) {
	if DefaultRounds != 32 {
		t.Fatalf("DefaultRounds = %d, want 32", DefaultRounds)
	}
}

func TestRoundConfigurationChangesDigest(t *testing.T) {
	message := []byte("pure recursive round smoke")
	r32 := NewWithEta(DefaultK, 32, DefaultOutput, DefaultEta)
	r48 := NewWithEta(DefaultK, 48, DefaultOutput, DefaultEta)
	if r32.HashBytes(message) != r32.HashBytes(message) {
		t.Fatal("32-round hash is not deterministic")
	}
	if r32.HashBytes(message) == r48.HashBytes(message) {
		t.Fatal("32-round and 48-round hashes unexpectedly matched")
	}
}

func TestSum256MatchesDefaultHashBytes(t *testing.T) {
	message := []byte("v1.3 fixed hash domain")
	sum := Sum256(message)
	got := hex.EncodeToString(sum[:])
	want := NewWithParams(DefaultK, DefaultRounds, DefaultOutput).HashBytes(message)
	if got != want {
		t.Fatalf("Sum256 mismatch:\n got %s\nwant %s", got, want)
	}
}

func TestXOFDomainSeparationAndPrefix(t *testing.T) {
	message := []byte("v1.3 xof domain")
	sum := Sum256(message)
	xof32 := XOF(message, 32)
	if hex.EncodeToString(sum[:]) == hex.EncodeToString(xof32) {
		t.Fatal("XOF(32) unexpectedly matched fixed hash digest")
	}

	xof16 := XOF(message, 16)
	xof64 := XOF(message, 64)
	if string(xof16) != string(xof64[:16]) {
		t.Fatal("XOF output is not prefix-stable")
	}
	if len(XOF(message, 0)) != 0 {
		t.Fatal("XOF length 0 should return an empty slice")
	}
	if XOF(message, XOFMaxOutput+1) != nil {
		t.Fatal("XOF beyond maximum should be rejected")
	}
}

func TestUnsupportedKPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("unsupported k should panic")
		}
	}()
	_ = NewWithParams(DefaultK+1, DefaultRounds, DefaultOutput)
}

func TestStateTraceMetrics(t *testing.T) {
	h := NewWithEta(3, 2, 256, 2)
	trace := h.TraceStateMetrics([]byte("trace"), 2)
	if len(trace) != 3 {
		t.Fatalf("unexpected trace length: got %d want 3", len(trace))
	}
	if trace[0].Fingerprint == "" || len(trace[0].BWords) == 0 || len(trace[0].EWords) == 0 || len(trace[0].SeedWords) == 0 {
		t.Fatal("trace row missing internal metrics")
	}
}

func schoolbookReference(a, b ringPoly) ringPoly {
	tmp := make([]int, 2*N-1)
	for i, ai := range a.coeffs {
		if ai == 0 {
			continue
		}
		for j, bj := range b.coeffs {
			if bj != 0 {
				tmp[i+j] = modQ(tmp[i+j] + ai*bj)
			}
		}
	}
	for d := 2*N - 2; d >= N; d-- {
		c := tmp[d]
		if c != 0 {
			tmp[d] = 0
			tmp[d-MID] = modQ(tmp[d-MID] - c)
			tmp[d-N] = modQ(tmp[d-N] - c)
		}
	}
	var out ringPoly
	copy(out.coeffs[:], tmp[:N])
	return out
}
