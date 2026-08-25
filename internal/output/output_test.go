package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"huashun-demo/internal/mdns"
	"huashun-demo/internal/probe"
)

func testAssets() []Asset {
	banner := &mdns.Banner{
		Services: map[string]*mdns.ServiceEntry{
			"9/tcp workstation": {
				Name:     "slw-nas [24:5e:be:69:a3:13]",
				IPv4:     []string{"127.0.0.1"},
				IPv6:     []string{"fe80::265e:beff:fe69:a313"},
				Hostname: "slw-nas.local",
				TTL:      10,
			},
			"5000/tcp http": {
				Name:     "slw-nas",
				IPv4:     []string{"127.0.0.1"},
				IPv6:     []string{"fe80::265e:beff:fe69:a313"},
				Hostname: "slw-nas.local",
				TTL:      10,
				TXT:      []mdns.KV{{Key: "path", Value: "/"}},
			},
			"device-info": {
				Name:     "slw-nas(AFP)",
				IPv4:     []string{"127.0.0.1"},
				IPv6:     []string{"fe80::265e:beff:fe69:a313"},
				Hostname: "slw-nas.local",
				TTL:      10,
				TXT:      []mdns.KV{{Key: "model", Value: "Xserve"}},
			},
		},
		PTRAnswers: []string{
			"_device-info._tcp.local",
			"_http._tcp.local",
			"_workstation._tcp.local",
		},
	}
	return FromResults([]probe.Result{
		{IP: "127.0.0.1", Port: 5353, Banner: banner},
	})
}

func TestRenderText(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderText(&buf, testAssets()); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	// 与任务示例同构的关键行（逐行包含性断言）
	wantLines := []string{
		"ip=127.0.0.1 port=5353 host=slw-nas.local",
		"services:",
		"  9/tcp workstation:",
		"    Name=slw-nas [24:5e:be:69:a3:13]",
		"    IPv4=127.0.0.1",
		"    IPv6=fe80::265e:beff:fe69:a313",
		"    Hostname=slw-nas.local",
		"    TTL=10",
		"  5000/tcp http:",
		"    path=/",
		"  device-info:",
		"    model=Xserve",
		"answers:",
		"  PTR:",
		"    _workstation._tcp.local",
		"    _http._tcp.local",
		"    _device-info._tcp.local",
	}
	for _, ln := range wantLines {
		if !strings.Contains(out, ln+"\n") {
			t.Errorf("text 输出缺少行 %q\n实际输出:\n%s", ln, out)
		}
	}
}

func TestRenderTextEmpty(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderText(&buf, nil); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != 0 {
		t.Errorf("空资产应输出空，实际 %q", buf.String())
	}
}

func TestRenderJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderJSON(&buf, testAssets()); err != nil {
		t.Fatal(err)
	}
	var got struct {
		Assets []Asset `json:"assets"`
	}
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("JSON 反序列化失败: %v\n%s", err, buf.String())
	}
	if len(got.Assets) != 1 {
		t.Fatalf("期望 1 个资产，实际 %d", len(got.Assets))
	}
	a := got.Assets[0]
	if a.IP != "127.0.0.1" || a.Port != 5353 || a.Host != "slw-nas.local" {
		t.Errorf("资产基础字段错误: %+v", a)
	}
	if len(a.Banner.Services) != 3 {
		t.Errorf("services 数量错误: %d", len(a.Banner.Services))
	}
	if e, ok := a.Banner.Services["5000/tcp http"]; !ok || len(e.TXT) != 1 || e.TXT[0].Value != "/" {
		t.Errorf("http 条目 JSON 深度错误: %+v", e)
	}
}

func TestRenderJSONL(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderJSONL(&buf, testAssets()); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 1 {
		t.Fatalf("期望 1 行，实际 %d", len(lines))
	}
	var a Asset
	if err := json.Unmarshal([]byte(lines[0]), &a); err != nil {
		t.Fatalf("JSONL 反序列化失败: %v", err)
	}
	if a.IP != "127.0.0.1" || a.Host != "slw-nas.local" {
		t.Errorf("JSONL 资产错误: %+v", a)
	}
}

func TestFromResultsHostFallback(t *testing.T) {
	// 无 hostname 的 banner：host 回退为 IP
	banner := &mdns.Banner{Services: map[string]*mdns.ServiceEntry{
		"5000/tcp http": {Name: "dev", TXT: nil},
	}}
	assets := FromResults([]probe.Result{{IP: "10.0.0.1", Port: 5353, Banner: banner}})
	if assets[0].Host != "10.0.0.1" {
		t.Errorf("Host 应回退为 IP，实际 %q", assets[0].Host)
	}
}
