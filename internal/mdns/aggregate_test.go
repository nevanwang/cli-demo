package mdns

import (
	"strings"
	"testing"
)

// nasRecords 构造任务示例（slw-nas NAS）的完整记录池：
// 识别轮（枚举 + 字典）+ 深挖轮（PTR _qdiscover）合并后的典型形态。
func nasRecords() []Record {
	const host = "slw-nas.local."
	svc := func(t string) string { return t }
	_ = svc
	records := []Record{
		// 枚举响应：6 个服务类型
		{Type: "PTR", Name: EnumName, Target: "_workstation._tcp.local."},
		{Type: "PTR", Name: EnumName, Target: "_http._tcp.local."},
		{Type: "PTR", Name: EnumName, Target: "_smb._tcp.local."},
		{Type: "PTR", Name: EnumName, Target: "_qdiscover._tcp.local."},
		{Type: "PTR", Name: EnumName, Target: "_device-info._tcp.local."},
		{Type: "PTR", Name: EnumName, Target: "_afpovertcp._tcp.local."},

		// _workstation（实例名带 MAC 后缀）
		{Type: "PTR", Name: "_workstation._tcp.local.", Target: "slw-nas [24:5e:be:69:a3:13]._workstation._tcp.local.", TTL: 10},
		{Type: "SRV", Name: "slw-nas [24:5e:be:69:a3:13]._workstation._tcp.local.", Target: host, Port: 9, TTL: 10},

		// _http（TXT path=/）
		{Type: "PTR", Name: "_http._tcp.local.", Target: "slw-nas._http._tcp.local.", TTL: 10},
		{Type: "SRV", Name: "slw-nas._http._tcp.local.", Target: host, Port: 5000, TTL: 10},
		{Type: "TXT", Name: "slw-nas._http._tcp.local.", TXT: []KV{{Key: "path", Value: "/"}}, TTL: 10},

		// _smb
		{Type: "PTR", Name: "_smb._tcp.local.", Target: "slw-nas._smb._tcp.local.", TTL: 10},
		{Type: "SRV", Name: "slw-nas._smb._tcp.local.", Target: host, Port: 445, TTL: 10},

		// _qdiscover（深挖轮发现，TXT 6 键）
		{Type: "PTR", Name: "_qdiscover._tcp.local.", Target: "slw-nas._qdiscover._tcp.local.", TTL: 10},
		{Type: "SRV", Name: "slw-nas._qdiscover._tcp.local.", Target: host, Port: 5000, TTL: 10},
		{Type: "TXT", Name: "slw-nas._qdiscover._tcp.local.", TTL: 10, TXT: []KV{
			{Key: "accessType", Value: "https"},
			{Key: "accessPort", Value: "86"},
			{Key: "model", Value: "TS-X64"},
			{Key: "displayModel", Value: "TS-464C"},
			{Key: "fwVer", Value: "5.2.9"},
			{Key: "fwBuildNum", Value: "20260214"},
		}},

		// _device-info（无 SRV，TXT model=Xserve）
		{Type: "PTR", Name: "_device-info._tcp.local.", Target: "slw-nas(AFP)._device-info._tcp.local.", TTL: 10},
		{Type: "TXT", Name: "slw-nas(AFP)._device-info._tcp.local.", TXT: []KV{{Key: "model", Value: "Xserve"}}, TTL: 10},

		// _afpovertcp
		{Type: "PTR", Name: "_afpovertcp._tcp.local.", Target: "slw-nas(AFP)._afpovertcp._tcp.local.", TTL: 10},
		{Type: "SRV", Name: "slw-nas(AFP)._afpovertcp._tcp.local.", Target: host, Port: 548, TTL: 10},

		// 主机地址
		{Type: "A", Name: host, IP: "192.168.1.100", TTL: 10},
		{Type: "AAAA", Name: host, IP: "fe80::265e:beff:fe69:a313", TTL: 10},
	}
	return records
}

// TestAggregateNasExample 验证聚合结果与任务示例逐字段同构（banner 深度验收核心）。
func TestAggregateNasExample(t *testing.T) {
	b := Aggregate(nasRecords())

	wantKeys := []string{
		"9/tcp workstation",
		"5000/tcp http",
		"445/tcp smb",
		"5000/tcp qdiscover",
		"device-info",
		"548/tcp afpovertcp",
	}
	if len(b.Services) != len(wantKeys) {
		t.Fatalf("期望 %d 个服务条目，实际 %d: %v", len(wantKeys), len(b.Services), b.Services)
	}
	for _, k := range wantKeys {
		if _, ok := b.Services[k]; !ok {
			t.Errorf("缺少服务条目 %q（现有: %v）", k, keysOf(b.Services))
		}
	}

	// workstation：实例名带 MAC
	ws := b.Services["9/tcp workstation"]
	if ws.Name != "slw-nas [24:5e:be:69:a3:13]" {
		t.Errorf("workstation Name = %q", ws.Name)
	}
	if ws.Hostname != "slw-nas.local" || ws.TTL != 10 {
		t.Errorf("workstation Hostname/TTL = %q/%d", ws.Hostname, ws.TTL)
	}
	if len(ws.IPv4) != 1 || ws.IPv4[0] != "192.168.1.100" {
		t.Errorf("workstation IPv4 = %v", ws.IPv4)
	}
	if len(ws.IPv6) != 1 || ws.IPv6[0] != "fe80::265e:beff:fe69:a313" {
		t.Errorf("workstation IPv6 = %v", ws.IPv6)
	}

	// http：TXT path=/
	http := b.Services["5000/tcp http"]
	if http.Name != "slw-nas" || len(http.TXT) != 1 || http.TXT[0].Key != "path" || http.TXT[0].Value != "/" {
		t.Errorf("http 条目错误: %+v", http)
	}

	// qdiscover：6 个 TXT 深度键
	qd := b.Services["5000/tcp qdiscover"]
	if len(qd.TXT) != 6 {
		t.Fatalf("qdiscover TXT 期望 6 项，实际 %d", len(qd.TXT))
	}
	wantTXT := "accessType=https|accessPort=86|model=TS-X64|displayModel=TS-464C|fwVer=5.2.9|fwBuildNum=20260214"
	var got []string
	for _, kv := range qd.TXT {
		got = append(got, kv.Key+"="+kv.Value)
	}
	if strings.Join(got, "|") != wantTXT {
		t.Errorf("qdiscover TXT = %v", got)
	}

	// device-info：无 SRV → key 为短名，hostname 回退唯一主机名
	di := b.Services["device-info"]
	if di.Name != "slw-nas(AFP)" {
		t.Errorf("device-info Name = %q", di.Name)
	}
	if di.Hostname != "slw-nas.local" {
		t.Errorf("device-info Hostname = %q（应回退唯一主机名）", di.Hostname)
	}
	if len(di.IPv4) != 1 || di.IPv4[0] != "192.168.1.100" {
		t.Errorf("device-info IPv4 = %v", di.IPv4)
	}
	if len(di.TXT) != 1 || di.TXT[0].Key != "model" || di.TXT[0].Value != "Xserve" {
		t.Errorf("device-info TXT 错误: %+v", di.TXT)
	}

	// answers PTR：6 个服务类型（去重、无尾点）
	wantPTR := "_afpovertcp._tcp.local,_device-info._tcp.local,_http._tcp.local,_qdiscover._tcp.local,_smb._tcp.local,_workstation._tcp.local"
	if strings.Join(b.PTRAnswers, ",") != wantPTR {
		t.Errorf("PTRAnswers = %v", b.PTRAnswers)
	}

	// PrimaryHost
	if h := b.PrimaryHost(); h != "slw-nas.local" {
		t.Errorf("PrimaryHost = %q", h)
	}
}

func keysOf(m map[string]*ServiceEntry) []string {
	var ks []string
	for k := range m {
		ks = append(ks, k)
	}
	return ks
}

func TestAggregateDuplicateRecords(t *testing.T) {
	recs := append(nasRecords(), nasRecords()...) // 两轮响应完全重复
	b := Aggregate(recs)
	if len(b.Services) != 6 {
		t.Errorf("重复记录应被去重，实际 %d 个条目", len(b.Services))
	}
}

func TestAggregateAdditionalOnly(t *testing.T) {
	// SRV/TXT 只出现在 additional 段（无对应 PTR）——应通过 inferServiceType 建立
	recs := []Record{
		{Type: "SRV", Name: "dev._airplay._tcp.local.", Target: "dev.local.", Port: 7000, TTL: 120},
		{Type: "TXT", Name: "dev._airplay._tcp.local.", TXT: []KV{{Key: "deviceid", Value: "AA:BB"}}, TTL: 120},
		{Type: "A", Name: "dev.local.", IP: "10.0.0.9", TTL: 120},
	}
	b := Aggregate(recs)
	e, ok := b.Services["7000/tcp airplay"]
	if !ok {
		t.Fatalf("期望 7000/tcp airplay 条目，实际 %v", keysOf(b.Services))
	}
	if e.Name != "dev" || e.Hostname != "dev.local" || e.IPv4[0] != "10.0.0.9" {
		t.Errorf("条目错误: %+v", e)
	}
	if len(e.TXT) != 1 || e.TXT[0].Key != "deviceid" {
		t.Errorf("TXT 错误: %+v", e.TXT)
	}
}

func TestAggregateMultiHostNoFallback(t *testing.T) {
	// 多主机名场景：无 SRV 条目不做唯一主机名回退
	recs := []Record{
		{Type: "PTR", Name: "_http._tcp.local.", Target: "a._http._tcp.local.", TTL: 10},
		{Type: "SRV", Name: "a._http._tcp.local.", Target: "host-a.local.", Port: 80, TTL: 10},
		{Type: "A", Name: "host-a.local.", IP: "10.0.0.1", TTL: 10},
		{Type: "PTR", Name: "_device-info._tcp.local.", Target: "b._device-info._tcp.local.", TTL: 10},
		{Type: "TXT", Name: "b._device-info._tcp.local.", TXT: []KV{{Key: "model", Value: "M"}}, TTL: 10},
		{Type: "A", Name: "host-b.local.", IP: "10.0.0.2", TTL: 10},
	}
	b := Aggregate(recs)
	di := b.Services["device-info"]
	if di.Hostname != "" {
		t.Errorf("多主机名时 device-info 不应回填 Hostname，实际 %q", di.Hostname)
	}
	h := b.Services["80/tcp http"]
	if h.Hostname != "host-a.local" || h.IPv4[0] != "10.0.0.1" {
		t.Errorf("http 条目错误: %+v", h)
	}
}

func TestAggregateSameKeyMultiInstance(t *testing.T) {
	// 同服务多实例：第二个实例 key 加序号
	recs := []Record{
		{Type: "PTR", Name: "_http._tcp.local.", Target: "dev1._http._tcp.local.", TTL: 10},
		{Type: "SRV", Name: "dev1._http._tcp.local.", Target: "h1.local.", Port: 80, TTL: 10},
		{Type: "PTR", Name: "_http._tcp.local.", Target: "dev2._http._tcp.local.", TTL: 10},
		{Type: "SRV", Name: "dev2._http._tcp.local.", Target: "h2.local.", Port: 80, TTL: 10},
	}
	b := Aggregate(recs)
	if _, ok := b.Services["80/tcp http"]; !ok {
		t.Errorf("缺少 80/tcp http")
	}
	if _, ok := b.Services["80/tcp http #2"]; !ok {
		t.Errorf("缺少 80/tcp http #2")
	}
}

func TestSplitServiceType(t *testing.T) {
	tests := []struct {
		in    string
		short string
		proto string
	}{
		{in: "_workstation._tcp.local.", short: "workstation", proto: "tcp"},
		{in: "_device-info._tcp.local.", short: "device-info", proto: "tcp"},
		{in: "_uscan._tcp.local.", short: "uscan", proto: "tcp"},
		{in: "_services._dns-sd._udp.local.", short: "services.dns-sd", proto: "udp"},
		{in: "local.", short: "", proto: ""},
		{in: "_tcp.local.", short: "", proto: "tcp"},
	}
	for _, tt := range tests {
		short, proto := splitServiceType(tt.in)
		if short != tt.short || proto != tt.proto {
			t.Errorf("splitServiceType(%q) = (%q, %q), 期望 (%q, %q)", tt.in, short, proto, tt.short, tt.proto)
		}
	}
}

func TestInferServiceType(t *testing.T) {
	if got := inferServiceType("dev._airplay._tcp.local."); got != "_airplay._tcp.local." {
		t.Errorf("inferServiceType = %q", got)
	}
	if got := inferServiceType("host.local."); got != "" {
		t.Errorf("主机名不应推断出服务类型: %q", got)
	}
	if got := inferServiceType("a.b.local."); got != "" {
		t.Errorf("非 _svc 结构不应推断: %q", got)
	}
}
