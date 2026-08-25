package probe

import (
	"context"
	"net"
	"testing"
	"time"

	"huashun-demo/internal/mdns/mdnstest"
	"huashun-demo/internal/target"
)

// TestScanUnicastFakeResponder 用 fake NAS 验证完整识别+深挖+聚合管线。
func TestScanUnicastFakeResponder(t *testing.T) {
	r, err := mdnstest.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	ctx := context.Background()
	targets := []target.Target{{IP: net.ParseIP("127.0.0.1"), Port: r.Addr().Port}}
	results := ScanUnicast(ctx, targets, Options{Timeout: 800 * time.Millisecond, Retries: 1, Concurrency: 4})

	if len(results) != 1 {
		t.Fatalf("期望 1 个资产，实际 %d", len(results))
	}
	res := results[0]
	if res.IP != "127.0.0.1" || res.Port != r.Addr().Port {
		t.Errorf("资产标识错误: %s:%d", res.IP, res.Port)
	}

	wantKeys := []string{
		"9/tcp workstation",
		"5000/tcp http",
		"445/tcp smb",
		"5000/tcp qdiscover",
		"device-info",
		"548/tcp afpovertcp",
	}
	if len(res.Banner.Services) != len(wantKeys) {
		t.Fatalf("期望 %d 个服务条目，实际 %d: %v", len(wantKeys), len(res.Banner.Services), res.Banner.Services)
	}
	for _, k := range wantKeys {
		if _, ok := res.Banner.Services[k]; !ok {
			t.Errorf("缺少条目 %q", k)
		}
	}

	// 深度抽查：qdiscover TXT 与 device-info 回退
	qd := res.Banner.Services["5000/tcp qdiscover"]
	if len(qd.TXT) != 6 || qd.TXT[0].Key != "accessType" || qd.TXT[0].Value != "https" {
		t.Errorf("qdiscover 深度 TXT 错误: %+v", qd.TXT)
	}
	di := res.Banner.Services["device-info"]
	if di.Hostname != "slw-nas.local" || di.TXT[0].Value != "Xserve" {
		t.Errorf("device-info 条目错误: %+v", di)
	}
	if h := res.Banner.PrimaryHost(); h != "slw-nas.local" {
		t.Errorf("PrimaryHost = %q", h)
	}
}

// TestScanUnicastNoResponder 验证无响应端口不产生资产、正确退出。
func TestScanUnicastNoResponder(t *testing.T) {
	ctx := context.Background()
	// 找一个确定没人监听的 UDP 端口
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	deadPort := c.LocalAddr().(*net.UDPAddr).Port
	c.Close()

	targets := []target.Target{{IP: net.ParseIP("127.0.0.1"), Port: deadPort}}
	results := ScanUnicast(ctx, targets, Options{Timeout: 150 * time.Millisecond, Retries: 0, Concurrency: 2})
	if len(results) != 0 {
		t.Errorf("无响应端口不应产生资产，实际 %d", len(results))
	}
}

// TestScanUnicastMultiPort 验证同一 IP 多端口目标（端口范围场景）。
func TestScanUnicastMultiPort(t *testing.T) {
	r, err := mdnstest.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	dead := r.Addr().Port + 1
	// 确认 dead 端口未被占用（大概率成立；被占用则跳过该断言维度）
	c, derr := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: dead})
	if derr == nil {
		c.Close()
	} else {
		t.Skipf("端口 %d 被占用，跳过多端口测试", dead)
	}

	ctx := context.Background()
	targets := []target.Target{
		{IP: net.ParseIP("127.0.0.1"), Port: r.Addr().Port},
		{IP: net.ParseIP("127.0.0.1"), Port: dead},
	}
	results := ScanUnicast(ctx, targets, Options{Timeout: 400 * time.Millisecond, Retries: 0, Concurrency: 4})
	if len(results) != 1 {
		t.Fatalf("期望仅 1 个资产（fake responder 端口），实际 %d", len(results))
	}
	if results[0].Port != r.Addr().Port {
		t.Errorf("资产端口错误: %d", results[0].Port)
	}
}

// TestScanUnicastRateLimit 验证限速器不阻碍基本功能。
func TestScanUnicastRateLimit(t *testing.T) {
	r, err := mdnstest.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	targets := []target.Target{{IP: net.ParseIP("127.0.0.1"), Port: r.Addr().Port}}
	results := ScanUnicast(ctx, targets, Options{
		Timeout: 800 * time.Millisecond, Retries: 1, Concurrency: 2, RateLimit: 500,
	})
	if len(results) != 1 {
		t.Fatalf("限速下仍应发现资产，实际 %d", len(results))
	}
}
