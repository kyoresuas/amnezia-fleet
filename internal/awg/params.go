package awg

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"sort"
	"strings"
)

type Params struct {
	Jc   uint16 `json:"jc"`
	Jmin uint16 `json:"jmin"`
	Jmax uint16 `json:"jmax"`

	S1 uint16 `json:"s1"`
	S2 uint16 `json:"s2"`
	S3 uint16 `json:"s3"`
	S4 uint16 `json:"s4"`

	H1 Range32 `json:"h1"`
	H2 Range32 `json:"h2"`
	H3 Range32 `json:"h3"`
	H4 Range32 `json:"h4"`

	I1 string `json:"i1,omitempty"`
	I2 string `json:"i2,omitempty"`
	I3 string `json:"i3,omitempty"`
	I4 string `json:"i4,omitempty"`
	I5 string `json:"i5,omitempty"`

	HeaderProtectionKey    Key     `json:"header_protection_key"`
	ContentPaddingAddition Range16 `json:"content_padding_addition"`
	RekeyAfterTime         Range16 `json:"rekey_after_time"`
	RekeyTimeout           Range16 `json:"rekey_timeout"`
	RejectAfterTime        Range16 `json:"reject_after_time"`
	KeepaliveTimeout       Range16 `json:"keepalive_timeout"`
	MaxHandshakeAttempts   Range16 `json:"max_handshake_attempts"`
	RandomTrailers         bool    `json:"random_trailers"`
	DisableCookies         bool    `json:"disable_cookies"`

	PersistentKeepalive Range16 `json:"persistent_keepalive"`
}

// минимум S1-S4 при HeaderProtectionKey
const headerProtectionNonce = 12

const maxJunkSize = 1024

const DefaultI1 = "<r 2><b 0x858000010001000000000669636c6f756403636f6d0000010001c00c000100010000105a00044d583737>"

// GenerateParams создаёт профиль обфускации со случайными H1-H4
func GenerateParams() (Params, error) {
	hpk, err := GenerateSymmetricKey()
	if err != nil {
		return Params{}, err
	}
	jc, err := randRange(4, 6)
	if err != nil {
		return Params{}, err
	}
	headers, err := randomHeaderRanges()
	if err != nil {
		return Params{}, err
	}
	return Params{
		Jc:                   uint16(jc),
		Jmin:                 10,
		Jmax:                 50,
		S1:                   headerProtectionNonce,
		S2:                   headerProtectionNonce,
		S3:                   headerProtectionNonce,
		S4:                   headerProtectionNonce,
		H1:                   headers[0],
		H2:                   headers[1],
		H3:                   headers[2],
		H4:                   headers[3],
		I1:                   DefaultI1,
		HeaderProtectionKey:  hpk,
		RekeyAfterTime:       Range16{Lo: 100, Hi: 120},
		RekeyTimeout:         Range16{Lo: 3, Hi: 7},
		RejectAfterTime:      Range16{Lo: 150, Hi: 180},
		KeepaliveTimeout:     Range16{Lo: 5, Hi: 15},
		MaxHandshakeAttempts: Range16{Lo: 15, Hi: 20},
		RandomTrailers:       true,
		DisableCookies:       true,
		PersistentKeepalive:  Range16{Lo: 25, Hi: 35},
	}, nil
}

// Validate проверяет профиль
func (p Params) Validate() error {
	var errs []error
	if p.Jmin > p.Jmax {
		errs = append(errs, errors.New("Jmin больше Jmax"))
	}
	if p.Jmax > maxJunkSize {
		errs = append(errs, fmt.Errorf("Jmax больше %d", maxJunkSize))
	}
	for i, s := range []uint16{p.S1, p.S2, p.S3, p.S4} {
		if s > maxJunkSize {
			errs = append(errs, fmt.Errorf("S%d больше %d", i+1, maxJunkSize))
		}
		if !p.HeaderProtectionKey.IsZero() && s < headerProtectionNonce {
			errs = append(errs, fmt.Errorf("S%d меньше %d при включённом HeaderProtectionKey", i+1, headerProtectionNonce))
		}
	}
	headers := []Range32{p.H1, p.H2, p.H3, p.H4}
	for i, h := range headers {
		if h.IsZero() {
			errs = append(errs, fmt.Errorf("H%d не задан", i+1))
			continue
		}
		for j := i + 1; j < len(headers); j++ {
			if h.Overlaps(headers[j]) {
				errs = append(errs, fmt.Errorf("H%d пересекается с H%d", i+1, j+1))
			}
		}
	}
	for i, tag := range []string{p.I1, p.I2, p.I3, p.I4, p.I5} {
		if err := ValidateSignature(tag); err != nil {
			errs = append(errs, fmt.Errorf("I%d: %w", i+1, err))
		}
	}
	return errors.Join(errs...)
}

var signatureTag = regexp.MustCompile(`<([a-z]+)(?:\s+([^<>]*))?>`)

// теги, которые понимают и ядро, и amneziawg-go
var supportedSignatureTags = map[string]bool{"b": true, "r": true, "rc": true, "rd": true, "t": true}

// ValidateSignature проверяет теги I1-I5
func ValidateSignature(s string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	rest := signatureTag.ReplaceAllString(s, "")
	if strings.TrimSpace(rest) != "" {
		return fmt.Errorf("лишние символы вне тегов: %q", rest)
	}
	for _, m := range signatureTag.FindAllStringSubmatch(s, -1) {
		if !supportedSignatureTags[m[1]] {
			return fmt.Errorf("тег <%s> поддерживается не всеми реализациями", m[1])
		}
	}
	return nil
}

// randomHeaderRanges генерирует четыре непересекающихся диапазона
func randomHeaderRanges() ([4]Range32, error) {
	const lowest, highest = 5, 1 << 31
	points := make([]uint32, 0, 8)
	seen := map[uint32]bool{}
	for len(points) < 8 {
		v, err := randRange(lowest, highest-1)
		if err != nil {
			return [4]Range32{}, err
		}
		if !seen[uint32(v)] {
			seen[uint32(v)] = true
			points = append(points, uint32(v))
		}
	}
	sort.Slice(points, func(i, j int) bool { return points[i] < points[j] })
	ranges := make([]Range32, 4)
	for i := range ranges {
		ranges[i] = Range32{Lo: points[2*i], Hi: points[2*i+1]}
	}
	var out [4]Range32
	for i := range out {
		idx, err := randRange(0, int64(len(ranges)-1))
		if err != nil {
			return [4]Range32{}, err
		}
		out[i] = ranges[idx]
		ranges = append(ranges[:idx], ranges[idx+1:]...)
	}
	return out, nil
}

// randRange возвращает криптостойкое случайное число в [lo, hi]
func randRange(lo, hi int64) (int64, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(hi-lo+1))
	if err != nil {
		return 0, fmt.Errorf("генерация случайного числа: %w", err)
	}
	return lo + n.Int64(), nil
}
