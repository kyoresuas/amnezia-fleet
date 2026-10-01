package awg

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

type ClientConfig struct {
	Description     string
	Host            string
	Port            uint16
	ServerPublicKey Key
	PrivateKey      Key
	PresharedKey    Key
	AddressV4       netip.Addr
	AddressV6       netip.Addr
	Subnet          netip.Prefix
	DNS             []string
	MTU             int
	AllowedIPs      []string
	Params          Params
}

const amneziaContainer = "amnezia-awg2"

const amneziaProtocolVersion = "3.1"

const amneziaFormatVersion = 1

const qCompressLevel = 8

var defaultAllowedIPs = []string{"0.0.0.0/0", "::/0"}

// allowedIPs возвращает заданные AllowedIPs или полный туннель по умолчанию
func (c ClientConfig) allowedIPs() []string {
	if len(c.AllowedIPs) == 0 {
		return defaultAllowedIPs
	}
	return c.AllowedIPs
}

// addresses возвращает адреса интерфейса клиента с префиксами хоста
func (c ClientConfig) addresses() []string {
	out := []string{netip.PrefixFrom(c.AddressV4, 32).String()}
	if c.AddressV6.IsValid() {
		out = append(out, netip.PrefixFrom(c.AddressV6, 128).String())
	}
	return out
}

// endpoint собирает host:port с квадратными скобками для IPv6-литерала
func (c ClientConfig) endpoint() string {
	return netipJoinHostPort(c.Host, c.Port)
}

// netipJoinHostPort аналог net.JoinHostPort без зависимости от пакета net
func netipJoinHostPort(host string, port uint16) string {
	if strings.Contains(host, ":") {
		return "[" + host + "]:" + strconv.Itoa(int(port))
	}
	return host + ":" + strconv.Itoa(int(port))
}

// onOff форматирует булев параметр AWG
func onOff(v bool) string {
	if v {
		return "on"
	}
	return "off"
}

// awgFields возвращает параметры обфускации ключ-значение
func (p Params) awgFields() [][2]string {
	fields := [][2]string{
		{"Jc", strconv.Itoa(int(p.Jc))},
		{"Jmin", strconv.Itoa(int(p.Jmin))},
		{"Jmax", strconv.Itoa(int(p.Jmax))},
		{"S1", strconv.Itoa(int(p.S1))},
		{"S2", strconv.Itoa(int(p.S2))},
		{"S3", strconv.Itoa(int(p.S3))},
		{"S4", strconv.Itoa(int(p.S4))},
		{"H1", p.H1.String()},
		{"H2", p.H2.String()},
		{"H3", p.H3.String()},
		{"H4", p.H4.String()},
		{"I1", p.I1},
		{"I2", p.I2},
		{"I3", p.I3},
		{"I4", p.I4},
		{"I5", p.I5},
	}
	if !p.HeaderProtectionKey.IsZero() {
		fields = append(fields, [2]string{"HeaderProtectionKey", p.HeaderProtectionKey.String()})
	}
	for _, r := range []struct {
		name string
		val  Range16
	}{
		{"ContentPaddingAddition", p.ContentPaddingAddition},
		{"RekeyAfterTime", p.RekeyAfterTime},
		{"RekeyTimeout", p.RekeyTimeout},
		{"RejectAfterTime", p.RejectAfterTime},
		{"KeepaliveTimeout", p.KeepaliveTimeout},
		{"MaxHandshakeAttempts", p.MaxHandshakeAttempts},
	} {
		if !r.val.IsZero() {
			fields = append(fields, [2]string{r.name, r.val.String()})
		}
	}
	fields = append(fields,
		[2]string{"RandomTrailers", onOff(p.RandomTrailers)},
		[2]string{"DisableCookies", onOff(p.DisableCookies)},
	)
	out := fields[:0]
	for _, f := range fields {
		if f[1] != "" {
			out = append(out, f)
		}
	}
	return out
}

// NativeConf рендерит конфиг для awg-quick и приложений AmneziaWG
func (c ClientConfig) NativeConf() string {
	var b strings.Builder
	line := func(k, v string) {
		if v != "" {
			fmt.Fprintf(&b, "%s = %s\n", k, v)
		}
	}
	b.WriteString("[Interface]\n")
	line("Address", strings.Join(c.addresses(), ", "))
	line("DNS", strings.Join(c.DNS, ", "))
	line("PrivateKey", c.PrivateKey.String())
	if c.MTU > 0 {
		line("MTU", strconv.Itoa(c.MTU))
	}
	for _, f := range c.Params.awgFields() {
		line(f[0], f[1])
	}
	b.WriteString("\n[Peer]\n")
	line("PublicKey", c.ServerPublicKey.String())
	if !c.PresharedKey.IsZero() {
		line("PresharedKey", c.PresharedKey.String())
	}
	line("AllowedIPs", strings.Join(c.allowedIPs(), ", "))
	line("Endpoint", c.endpoint())
	if !c.Params.PersistentKeepalive.IsZero() {
		line("PersistentKeepalive", c.Params.PersistentKeepalive.String())
	}
	return b.String()
}

// amneziaJSON собирает JSON в формате клиента Amnezia
func (c ClientConfig) amneziaJSON() (map[string]any, error) {
	awgFields := c.Params.awgFields()

	lastConfig := map[string]any{
		"config":          c.NativeConf(),
		"hostName":        c.Host,
		"port":            int(c.Port),
		"client_ip":       c.AddressV4.String(),
		"client_priv_key": c.PrivateKey.String(),
		"client_pub_key":  c.PrivateKey.PublicKey().String(),
		"server_pub_key":  c.ServerPublicKey.String(),
		"clientId":        c.PrivateKey.PublicKey().String(),
		"allowed_ips":     c.allowedIPs(),
	}
	if !c.PresharedKey.IsZero() {
		lastConfig["psk_key"] = c.PresharedKey.String()
	}
	if !c.Params.PersistentKeepalive.IsZero() {
		lastConfig["persistent_keep_alive"] = c.Params.PersistentKeepalive.String()
	}
	if c.MTU > 0 {
		lastConfig["mtu"] = strconv.Itoa(c.MTU)
	}
	for _, f := range awgFields {
		lastConfig[f[0]] = f[1]
	}
	lastConfigRaw, err := json.Marshal(lastConfig)
	if err != nil {
		return nil, fmt.Errorf("сериализация last_config: %w", err)
	}

	server := map[string]any{
		"port":             strconv.Itoa(int(c.Port)),
		"transport_proto":  "udp",
		"protocol_version": amneziaProtocolVersion,
		"last_config":      string(lastConfigRaw),
		// клиент Amnezia пишет I1-I5 всегда
		"I1": c.Params.I1,
		"I2": c.Params.I2,
		"I3": c.Params.I3,
		"I4": c.Params.I4,
		"I5": c.Params.I5,
	}
	if c.Subnet.IsValid() {
		server["subnet_address"] = c.Subnet.Addr().String()
		server["subnet_cidr"] = strconv.Itoa(c.Subnet.Bits())
	}
	for _, f := range awgFields {
		server[f[0]] = f[1]
	}

	root := map[string]any{
		"format_version":   amneziaFormatVersion,
		"hostName":         c.Host,
		"defaultContainer": amneziaContainer,
		"containers": []any{map[string]any{
			"container": amneziaContainer,
			"awg":       server,
		}},
	}
	if c.Description != "" {
		root["description"] = c.Description
	}
	if len(c.DNS) > 0 {
		root["dns1"] = c.DNS[0]
	}
	if len(c.DNS) > 1 {
		root["dns2"] = c.DNS[1]
	}
	return root, nil
}

// AmneziaURL кодирует конфиг в ссылку vpn:// для импорта в клиент Amnezia
func (c ClientConfig) AmneziaURL() (string, error) {
	root, err := c.amneziaJSON()
	if err != nil {
		return "", err
	}
	raw, err := json.Marshal(root)
	if err != nil {
		return "", fmt.Errorf("сериализация конфига: %w", err)
	}
	compressed, err := qCompress(raw, qCompressLevel)
	if err != nil {
		return "", err
	}
	return "vpn://" + base64.RawURLEncoding.EncodeToString(compressed), nil
}

// DecodeAmneziaURL раскодирует ссылку vpn:// в JSON
func DecodeAmneziaURL(url string) ([]byte, error) {
	data, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(strings.TrimSpace(url), "vpn://"))
	if err != nil {
		return nil, fmt.Errorf("base64: %w", err)
	}
	if len(data) < 4 {
		return nil, fmt.Errorf("слишком короткие данные")
	}
	r, err := zlib.NewReader(bytes.NewReader(data[4:]))
	if err != nil {
		// клиент Amnezia допускает несжатые данные
		return data, nil
	}
	defer r.Close()
	var out bytes.Buffer
	if _, err := out.ReadFrom(r); err != nil {
		return nil, fmt.Errorf("zlib: %w", err)
	}
	return out.Bytes(), nil
}

// qCompress повторяет формат Qt qCompress
func qCompress(data []byte, level int) ([]byte, error) {
	var buf bytes.Buffer
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(data)))
	buf.Write(size[:])
	w, err := zlib.NewWriterLevel(&buf, level)
	if err != nil {
		return nil, fmt.Errorf("zlib: %w", err)
	}
	if _, err := w.Write(data); err != nil {
		return nil, fmt.Errorf("zlib: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("zlib: %w", err)
	}
	return buf.Bytes(), nil
}
