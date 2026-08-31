package v39

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"html"
	"io"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

type decodeCandidate struct {
	data   []byte
	origin string
}

// MaterializeText returns the original text plus bounded decoded variants.
// Decoding is breadth-first and de-duplicated by content hash.
func MaterializeText(path string, data []byte, limits Limits) []Material {
	text, ok := decodeText(data)
	if !ok || text == "" {
		return nil
	}

	out := []Material{{Path: path, Text: text, Origin: "raw"}}
	seen := map[[32]byte]struct{}{sha256.Sum256([]byte(text)): {}}
	type queueItem struct {
		material Material
	}
	queue := []queueItem{{material: out[0]}}
	decodedBytes := int64(0)

	for len(queue) > 0 && len(out) < limits.MaxDecodedVariantsPerFile+1 {
		item := queue[0]
		queue = queue[1:]
		if item.material.Depth >= limits.MaxDecodeDepth {
			continue
		}

		for _, candidate := range decodeCandidates(item.material.Text, limits) {
			if len(candidate.data) == 0 || int64(len(candidate.data)) > limits.MaxDecodedBytesPerFile-decodedBytes {
				continue
			}
			decoded, ok := decodeText(candidate.data)
			if !ok {
				continue
			}
			decoded = strings.TrimSpace(decoded)
			if decoded == "" || decoded == strings.TrimSpace(item.material.Text) {
				continue
			}
			hash := sha256.Sum256([]byte(decoded))
			if _, exists := seen[hash]; exists {
				continue
			}
			seen[hash] = struct{}{}
			origin := candidate.origin
			if item.material.Origin != "raw" {
				origin = item.material.Origin + ">" + origin
			}
			material := Material{
				Path:    path,
				Text:    decoded,
				Origin:  origin,
				Depth:   item.material.Depth + 1,
				Decoded: true,
			}
			out = append(out, material)
			queue = append(queue, queueItem{material: material})
			decodedBytes += int64(len(decoded))
			if len(out) >= limits.MaxDecodedVariantsPerFile+1 {
				break
			}
		}
	}
	return out
}

func decodeCandidates(text string, limits Limits) []decodeCandidate {
	var out []decodeCandidate
	add := func(data []byte, origin string) {
		if len(data) == 0 || int64(len(data)) > limits.MaxDecodedBytesPerFile {
			return
		}
		if expanded, kind, ok := maybeDecompress(data, limits.MaxDecodedBytesPerFile); ok {
			out = append(out, decodeCandidate{data: expanded, origin: origin + ">" + kind})
			return
		}
		out = append(out, decodeCandidate{data: data, origin: origin})
	}

	if strings.Contains(text, "&") {
		if decoded := html.UnescapeString(text); decoded != text {
			add([]byte(decoded), "html-entity")
		}
	}
	if strings.Contains(text, "%") {
		if decoded, err := url.PathUnescape(text); err == nil && decoded != text {
			add([]byte(decoded), "url")
		}
	}
	if strings.Contains(text, "\\") {
		if decoded, changed := decodeBackslashEscapes(text); changed {
			add([]byte(decoded), "escaped")
		}
	}

	for _, token := range base64Tokens(text, 8) {
		for _, enc := range []*base64.Encoding{
			base64.StdEncoding,
			base64.RawStdEncoding,
			base64.URLEncoding,
			base64.RawURLEncoding,
		} {
			decoded, err := enc.DecodeString(token)
			if err == nil && plausibleDecoded(decoded) {
				add(decoded, "base64")
				break
			}
		}
	}
	for _, token := range hexTokens(text, 6) {
		decoded, err := hex.DecodeString(token)
		if err == nil && plausibleDecoded(decoded) {
			add(decoded, "hex")
		}
	}
	return out
}

func decodeText(data []byte) (string, bool) {
	if len(data) == 0 {
		return "", false
	}
	if utf8.Valid(data) && printableRatio(data) >= 0.70 {
		return string(data), true
	}
	if decoded, ok := decodeUTF16(data); ok {
		return decoded, true
	}
	return "", false
}

func decodeUTF16(data []byte) (string, bool) {
	if len(data) < 4 {
		return "", false
	}
	start := 0
	little, big := false, false
	switch {
	case data[0] == 0xff && data[1] == 0xfe:
		little, start = true, 2
	case data[0] == 0xfe && data[1] == 0xff:
		big, start = true, 2
	default:
		var evenNUL, oddNUL int
		for i, b := range data[:min(len(data), 512)] {
			if b == 0 {
				if i%2 == 0 {
					evenNUL++
				} else {
					oddNUL++
				}
			}
		}
		little = oddNUL >= 2 && oddNUL > evenNUL*2
		big = evenNUL >= 2 && evenNUL > oddNUL*2
	}
	if !little && !big {
		return "", false
	}
	units := make([]uint16, 0, (len(data)-start)/2)
	for i := start; i+1 < len(data); i += 2 {
		if little {
			units = append(units, uint16(data[i])|uint16(data[i+1])<<8)
		} else {
			units = append(units, uint16(data[i])<<8|uint16(data[i+1]))
		}
	}
	if len(units) == 0 {
		return "", false
	}
	decoded := string(utf16.Decode(units))
	if printableRatio([]byte(decoded)) < 0.70 {
		return "", false
	}
	return decoded, true
}

func decodeBackslashEscapes(s string) (string, bool) {
	var b strings.Builder
	b.Grow(len(s))
	changed := false
	for i := 0; i < len(s); {
		if s[i] != '\\' || i+1 >= len(s) {
			b.WriteByte(s[i])
			i++
			continue
		}
		switch s[i+1] {
		case 'x':
			if i+3 < len(s) {
				if v, err := strconv.ParseUint(s[i+2:i+4], 16, 8); err == nil {
					b.WriteByte(byte(v))
					i += 4
					changed = true
					continue
				}
			}
		case 'u':
			if i+5 < len(s) {
				if v, err := strconv.ParseUint(s[i+2:i+6], 16, 16); err == nil {
					b.WriteRune(rune(v))
					i += 6
					changed = true
					continue
				}
			}
		case 'n':
			b.WriteByte('\n')
			i += 2
			changed = true
			continue
		case 'r':
			b.WriteByte('\r')
			i += 2
			changed = true
			continue
		case 't':
			b.WriteByte('\t')
			i += 2
			changed = true
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String(), changed
}

func base64Tokens(s string, maxTokens int) []string {
	return tokenRuns(s, maxTokens, 24, 256<<10, func(c byte) bool {
		return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("+/=_-", rune(c))
	}, func(token string) bool {
		trimmed := strings.TrimSpace(token)
		return len(trimmed) >= 24 && (len(trimmed)%4 == 0 || !strings.Contains(trimmed, "="))
	})
}

func hexTokens(s string, maxTokens int) []string {
	return tokenRuns(s, maxTokens, 32, 256<<10, func(c byte) bool {
		return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
	}, func(token string) bool { return len(token)%2 == 0 })
}

func tokenRuns(s string, maxTokens, minLen, maxLen int, allowed func(byte) bool, validate func(string) bool) []string {
	out := make([]string, 0, maxTokens)
	for i := 0; i < len(s) && len(out) < maxTokens; {
		for i < len(s) && !allowed(s[i]) {
			i++
		}
		start := i
		for i < len(s) && allowed(s[i]) && i-start <= maxLen {
			i++
		}
		if i-start >= minLen {
			token := s[start:i]
			if validate(token) {
				out = append(out, token)
			}
		}
		if i-start > maxLen {
			for i < len(s) && allowed(s[i]) {
				i++
			}
		}
	}
	return out
}

func plausibleDecoded(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	if isCompressed(data) {
		return true
	}
	return utf8.Valid(data) && printableRatio(data) >= 0.78
}

func printableRatio(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	printable := 0
	for _, b := range data {
		if b == '\n' || b == '\r' || b == '\t' || b >= 0x20 && b < 0x7f || b >= 0x80 {
			printable++
		}
	}
	return float64(printable) / float64(len(data))
}

func isCompressed(data []byte) bool {
	return len(data) >= 2 && (data[0] == 0x1f && data[1] == 0x8b || data[0] == 0x78)
}

func maybeDecompress(data []byte, maxBytes int64) ([]byte, string, bool) {
	if len(data) < 2 {
		return nil, "", false
	}
	if data[0] == 0x1f && data[1] == 0x8b {
		r, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, "", false
		}
		defer r.Close()
		out, err := readLimited(r, maxBytes)
		return out, "gzip", err == nil
	}
	if data[0] == 0x78 {
		r, err := zlib.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, "", false
		}
		defer r.Close()
		out, err := readLimited(r, maxBytes)
		return out, "zlib", err == nil
	}
	return nil, "", false
}

func readLimited(r io.Reader, maxBytes int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, io.ErrUnexpectedEOF
	}
	return data, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
