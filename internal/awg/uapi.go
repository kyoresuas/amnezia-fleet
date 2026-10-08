package awg

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// Hex возвращает ключ в hex, как его ждёт UAPI
func (k Key) Hex() string {
	return hex.EncodeToString(k[:])
}

// UAPI собирает строки устройства для UAPI amneziawg-go: приватный ключ и параметры обфускации
func (p Params) UAPI(privateKey Key) string {
	var b strings.Builder
	line := func(k, v string) {
		if v != "" {
			fmt.Fprintf(&b, "%s=%s\n", k, v)
		}
	}
	line("private_key", privateKey.Hex())
	line("jc", strconv.Itoa(int(p.Jc)))
	line("jmin", strconv.Itoa(int(p.Jmin)))
	line("jmax", strconv.Itoa(int(p.Jmax)))
	line("s1", strconv.Itoa(int(p.S1)))
	line("s2", strconv.Itoa(int(p.S2)))
	line("s3", strconv.Itoa(int(p.S3)))
	line("s4", strconv.Itoa(int(p.S4)))
	for i, h := range []Range32{p.H1, p.H2, p.H3, p.H4} {
		if !h.IsZero() {
			line("h"+strconv.Itoa(i+1), h.String())
		}
	}
	line("i1", p.I1)
	line("i2", p.I2)
	line("i3", p.I3)
	line("i4", p.I4)
	line("i5", p.I5)
	if !p.HeaderProtectionKey.IsZero() {
		line("header_protection_key", p.HeaderProtectionKey.Hex())
	}
	for _, r := range []struct {
		key string
		val Range16
	}{
		{"content_padding_addition", p.ContentPaddingAddition},
		{"rekey_after_time", p.RekeyAfterTime},
		{"rekey_timeout", p.RekeyTimeout},
		{"reject_after_time", p.RejectAfterTime},
		{"keepalive_timeout", p.KeepaliveTimeout},
		{"max_handshake_attempts", p.MaxHandshakeAttempts},
	} {
		if !r.val.IsZero() {
			line(r.key, r.val.String())
		}
	}
	line("random_trailers", strconv.FormatBool(p.RandomTrailers))
	line("disable_cookies", strconv.FormatBool(p.DisableCookies))
	return b.String()
}
