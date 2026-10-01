package awg

import (
	"fmt"
	"strconv"
	"strings"
)

type Range32 struct {
	Lo uint32
	Hi uint32
}

type Range16 struct {
	Lo uint16
	Hi uint16
}

// IsZero сообщает, что диапазон не задан
func (r Range32) IsZero() bool { return r.Lo == 0 && r.Hi == 0 }

// Overlaps проверяет пересечение двух диапазонов
func (r Range32) Overlaps(o Range32) bool { return r.Lo <= o.Hi && o.Lo <= r.Hi }

// String форматирует диапазон как в конфиге AWG: "a" или "a-b"
func (r Range32) String() string {
	if r.Lo == r.Hi {
		return strconv.FormatUint(uint64(r.Lo), 10)
	}
	return fmt.Sprintf("%d-%d", r.Lo, r.Hi)
}

// Netlink кодирует диапазон в u64 для генерик-netlink версии 3 (hi<<32 | lo)
func (r Range32) Netlink() uint64 { return uint64(r.Hi)<<32 | uint64(r.Lo) }

// Range32FromNetlink декодирует диапазон из u64 netlink-атрибута
func Range32FromNetlink(v uint64) Range32 {
	return Range32{Lo: uint32(v), Hi: uint32(v >> 32)}
}

// ParseRange32 разбирает "a" или "a-b"
func ParseRange32(s string) (Range32, error) {
	lo, hi, err := parseRange(s, 32)
	if err != nil {
		return Range32{}, err
	}
	return Range32{Lo: uint32(lo), Hi: uint32(hi)}, nil
}

// IsZero сообщает, что диапазон не задан
func (r Range16) IsZero() bool { return r.Lo == 0 && r.Hi == 0 }

// String форматирует диапазон как в конфиге AWG: "a" или "a-b"
func (r Range16) String() string {
	if r.Lo == r.Hi {
		return strconv.FormatUint(uint64(r.Lo), 10)
	}
	return fmt.Sprintf("%d-%d", r.Lo, r.Hi)
}

// Netlink кодирует диапазон в u32 для генерик-netlink версии 3 (hi<<16 | lo)
func (r Range16) Netlink() uint32 { return uint32(r.Hi)<<16 | uint32(r.Lo) }

// Range16FromNetlink декодирует диапазон из u32 netlink-атрибута
func Range16FromNetlink(v uint32) Range16 {
	return Range16{Lo: uint16(v), Hi: uint16(v >> 16)}
}

// ParseRange16 разбирает "a" или "a-b"
func ParseRange16(s string) (Range16, error) {
	lo, hi, err := parseRange(s, 16)
	if err != nil {
		return Range16{}, err
	}
	return Range16{Lo: uint16(lo), Hi: uint16(hi)}, nil
}

// parseRange разбирает строку диапазона
func parseRange(s string, bits int) (uint64, uint64, error) {
	s = strings.TrimSpace(s)
	loStr, hiStr, isRange := strings.Cut(s, "-")
	lo, err := strconv.ParseUint(strings.TrimSpace(loStr), 10, bits)
	if err != nil {
		return 0, 0, fmt.Errorf("диапазон %q: %w", s, err)
	}
	hi := lo
	if isRange {
		hi, err = strconv.ParseUint(strings.TrimSpace(hiStr), 10, bits)
		if err != nil {
			return 0, 0, fmt.Errorf("диапазон %q: %w", s, err)
		}
	}
	if hi < lo {
		return 0, 0, fmt.Errorf("диапазон %q: верхняя граница меньше нижней", s)
	}
	return lo, hi, nil
}

// MarshalText сериализует диапазон в строку "a-b", пустой, в пустую строку
func (r Range32) MarshalText() ([]byte, error) {
	if r.IsZero() {
		return []byte{}, nil
	}
	return []byte(r.String()), nil
}

// UnmarshalText разбирает диапазон из строки
func (r *Range32) UnmarshalText(b []byte) error {
	if len(b) == 0 {
		*r = Range32{}
		return nil
	}
	parsed, err := ParseRange32(string(b))
	if err != nil {
		return err
	}
	*r = parsed
	return nil
}

// MarshalText сериализует диапазон в строку "a-b", пустой, в пустую строку
func (r Range16) MarshalText() ([]byte, error) {
	if r.IsZero() {
		return []byte{}, nil
	}
	return []byte(r.String()), nil
}

// UnmarshalText разбирает диапазон из строки
func (r *Range16) UnmarshalText(b []byte) error {
	if len(b) == 0 {
		*r = Range16{}
		return nil
	}
	parsed, err := ParseRange16(string(b))
	if err != nil {
		return err
	}
	*r = parsed
	return nil
}
