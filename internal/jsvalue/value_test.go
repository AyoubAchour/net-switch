package jsvalue

import (
	"math"
	"testing"
)

func TestNumberStringGrammar(t *testing.T) {
	for _, s := range []string{"inf", "Inf", "-infinity", "+infinity", "0x1p3", "0X1.2", "+0x10", "-0b10", "1_000", "infinity"} {
		if !math.IsNaN(Number(s)) {
			t.Fatalf("Number(%q) must be NaN", s)
		}
	}
	for s, want := range map[string]float64{"0x10": 16, "0b10": 2, "0o10": 8, "010": 10, ".5": .5, "5.": 5, "1e2": 100, "0x100000000000000000000": math.Exp2(80)} {
		if Number(s) != want {
			t.Fatalf("Number(%q) got %v want %v", s, Number(s), want)
		}
	}
	for _, s := range []string{"Infinity", "+Infinity", "1e400"} {
		if !math.IsInf(Number(s), 1) {
			t.Fatal(s)
		}
	}
	if !math.Signbit(Number("-0")) {
		t.Fatal("negative zero lost")
	}
}
