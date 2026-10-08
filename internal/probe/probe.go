// Package probe
package probe

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/tuntest"

	"github.com/kyoresuas/amnezia-fleet/internal/agentapi"
	"github.com/kyoresuas/amnezia-fleet/internal/awg"
)

type Prober struct {
	privateKey  awg.Key
	timeout     time.Duration
	concurrency int
	log         *slog.Logger
}

// New создаёт проверяющего с ключом наблюдателя
func New(privateKey awg.Key, timeout time.Duration, concurrency int, log *slog.Logger) *Prober {
	return &Prober{privateKey: privateKey, timeout: timeout, concurrency: max(concurrency, 1), log: log}
}

// CheckAll проверяет кластеры параллельно, а адреса одного кластера по очереди
func (p *Prober) CheckAll(ctx context.Context, targets []agentapi.ProbeTarget) []agentapi.ProbeResult {
	results := make([]agentapi.ProbeResult, len(targets))
	// параллельные рукопожатия одним ключом ядро отвергает по временной метке
	byCluster := map[string][]int{}
	for i, t := range targets {
		byCluster[t.ClusterID] = append(byCluster[t.ClusterID], i)
	}
	sem := make(chan struct{}, p.concurrency)
	var wg sync.WaitGroup
	for _, idx := range byCluster {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			for _, i := range idx {
				results[i] = p.Check(ctx, targets[i])
			}
		}()
	}
	wg.Wait()
	return results
}

// Check поднимает временное устройство и ждёт рукопожатия
func (p *Prober) Check(ctx context.Context, t agentapi.ProbeTarget) agentapi.ProbeResult {
	res := agentapi.ProbeResult{AddressID: t.AddressID}
	start := time.Now()
	dev := device.NewDevice(tuntest.NewChannelTUN().TUN(), conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	defer dev.Close()
	if err := dev.Up(); err != nil {
		res.Error = "up: " + err.Error()
		return res
	}
	if err := dev.IpcSet(uapiConfig(p.privateKey, t)); err != nil {
		res.Error = "config: " + err.Error()
		return res
	}
	deadline := time.NewTimer(p.timeout)
	defer deadline.Stop()
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			res.Error = ctx.Err().Error()
			return res
		case <-deadline.C:
			res.Error = fmt.Sprintf("нет рукопожатия за %s", p.timeout)
			return res
		case <-tick.C:
			ok, err := handshakeDone(dev)
			if err != nil {
				res.Error = err.Error()
				return res
			}
			if ok {
				rtt := int(time.Since(start).Milliseconds())
				res.OK, res.RTTMs = true, &rtt
				return res
			}
		}
	}
}

// handshakeDone сообщает, что у единственного пира появилось рукопожатие
func handshakeDone(dev *device.Device) (bool, error) {
	out, err := dev.IpcGet()
	if err != nil {
		return false, err
	}
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "last_handshake_time_sec="); ok {
			sec, _ := strconv.ParseInt(v, 10, 64)
			return sec > 0, nil
		}
	}
	return false, nil
}

// uapiConfig собирает конфигурацию UAPI
func uapiConfig(priv awg.Key, t agentapi.ProbeTarget) string {
	return t.Params.UAPI(priv) + fmt.Sprintf("public_key=%s\nendpoint=%s\npersistent_keepalive_interval=1\n",
		t.ServerPublicKey.Hex(), t.Endpoint)
}
