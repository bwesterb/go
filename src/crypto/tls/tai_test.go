package tls

import (
	"encoding/hex"
	"testing"
)

func TestTAIParsing(t *testing.T) {
	for _, tc := range []struct {
		text string
		hex  string
	}{
		{"0", "00"},
		{"32473", "81fd59"},
		{"32473.1", "81fd5901"},
		{"32473.4.40.400.4000.40000.400000.4000000.40000000.400000000.4000000000",
			"81fd59042883109f2082b84098b50081f492009389b40081bede88008ef3acd000"},
		{"32473.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1",
			"81fd5901010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101"},
	} {
		var tai TrustAnchorIdentifier
		if err := tai.UnmarshalText([]byte(tc.text)); err != nil {
			t.Fatal(err)
		}
		if tai.String() != tc.text {
			t.Fatalf("%s ≠ %s", tc.text, tai.String())
		}
		hex2 := hex.EncodeToString(tai)

		if hex2 != tc.hex {
			t.Fatalf("%s ≠ %s", tc.hex, hex2)
		}
	}

	for _, tc := range []struct{ hex, errString string }{
		{"", "TrustAnchorIdentifier: must have at least one segment"},
		{"8001", "TrustAnchorIdentifier: not normalized; starts with 0x80"},
		{"ff81818101", "TrustAnchorIdentifier: overflow of sub-identifier 0"},
		{"81", "TrustAnchorIdentifier: ends on continuation"},
	} {
		var tai TrustAnchorIdentifier
		bin, _ := hex.DecodeString(tc.hex)
		if err := tai.UnmarshalBinary(bin); err == nil || err.Error() != tc.errString {
			t.Fatalf("%s: %s ≠ %v", tc.hex, tc.errString, err)
		}
	}

	for _, tc := range []struct{ s, errString string }{
		{"12345678900", "TrustAnchorIdentifier: subidentifier 0: strconv.ParseUint: parsing \"12345678900\": value out of range"},
		{"1..1", "TrustAnchorIdentifier: subidentifier 1: strconv.ParseUint: parsing \"\": invalid syntax"},
		{"-1", "TrustAnchorIdentifier: subidentifier 0: strconv.ParseUint: parsing \"-1\": invalid syntax"},
	} {
		var tai TrustAnchorIdentifier
		if err := tai.UnmarshalText([]byte(tc.s)); err == nil || err.Error() != tc.errString {
			t.Fatalf("%s: %s ≠ %v", tc.s, tc.errString, err)
		}
	}
}
