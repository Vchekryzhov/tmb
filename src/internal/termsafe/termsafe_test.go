package termsafe

import "testing"

func TestTextQuotesInvalidUTF8(t *testing.T) {
	if got := Text("/tmp/\xffexe"); got != `"/tmp/\xffexe"` {
		t.Errorf("Text = %s", got)
	}
	if got := Text("/usr/bin/id"); got != "/usr/bin/id" {
		t.Errorf("Text changed a plain path: %s", got)
	}
}

func TestTextQuotesControlAndFormatRunes(t *testing.T) {
	for in, want := range map[string]string{
		"n\x1b[2Ax":   `"n\x1b[2Ax"`,
		"n\u009b2A":   `"n\u009b2A"`,
		"n\u202ex":    `"n\u202ex"`,
		"n\x7f":       `"n\x7f"`,
		"plain-nonce": "plain-nonce",
	} {
		if got := Text(in); got != want {
			t.Errorf("Text(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestJSONEscapesNonPrintable(t *testing.T) {
	got := JSON([]byte("[\"\u009b2A\",\"x\x7f\",\"A=\U000E0041\",\"ok\"]"))
	want := `["\u009b2A","x\u007f","A=\udb40\udc41","ok"]`
	if got != want {
		t.Errorf("JSON = %s, want %s", got, want)
	}
}
