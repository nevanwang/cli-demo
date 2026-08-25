package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"huashun-demo/internal/mdns/mdnstest"
)

// runE2E 启动 fake NAS 并以给定参数跑完整 CLI 流程，返回 (exitCode, stdout)。
func runE2E(t *testing.T, extraArgs ...string) (int, string) {
	t.Helper()
	r, err := mdnstest.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	var out, errBuf bytes.Buffer
	args := append([]string{
		"-p", strconv.Itoa(r.Addr().Port),
		"-c", "8",
		"-timeout", "1s",
	}, extraArgs...)
	code := run(context.Background(), args, &out, &errBuf)
	if errBuf.Len() > 0 {
		t.Logf("stderr: %s", errBuf.String())
	}
	return code, out.String()
}

// TestE2ETextFormat 验收：text 输出与任务示例 banner 逐字段同构。
func TestE2ETextFormat(t *testing.T) {
	code, out := runE2E(t, "-f", "text", "127.0.0.1")
	if code != 0 {
		t.Fatalf("退出码 %d，输出:\n%s", code, out)
	}

	// banner 深度验收：示例中的每个字段都必须出现
	wantLines := []string{
		"services:",
		// 9/tcp workstation
		"  9/tcp workstation:",
		"    Name=slw-nas [24:5e:be:69:a3:13]",
		"    IPv4=127.0.0.1",
		"    IPv6=fe80::265e:beff:fe69:a313",
		"    Hostname=slw-nas.local",
		"    TTL=10",
		// 5000/tcp http
		"  5000/tcp http:",
		"    Name=slw-nas",
		"    path=/",
		// 445/tcp smb
		"  445/tcp smb:",
		// 5000/tcp qdiscover（TXT 深度链）
		"  5000/tcp qdiscover:",
		"    accessType=https,accessPort=86,model=TS-X64,displayModel=TS-464C,fwVer=5.2.9,fwBuildNum=20260214",
		// device-info（无 SRV，短名 key + TXT）
		"  device-info:",
		"    Name=slw-nas(AFP)",
		"    model=Xserve",
		// 548/tcp afpovertcp
		"  548/tcp afpovertcp:",
		// answers PTR 聚合
		"answers:",
		"  PTR:",
		"    _workstation._tcp.local",
		"    _http._tcp.local",
		"    _smb._tcp.local",
		"    _qdiscover._tcp.local",
		"    _device-info._tcp.local",
		"    _afpovertcp._tcp.local",
	}
	for _, wl := range wantLines {
		if !strings.Contains(out, wl+"\n") {
			t.Errorf("E2E text 输出缺少 %q\n完整输出:\n%s", wl, out)
		}
	}

	// 资产头行（端口为动态分配值，仅断言前缀）
	if !strings.HasPrefix(out, "ip=127.0.0.1 port=") || !strings.Contains(out, " host=slw-nas.local\n") {
		t.Errorf("资产头行错误，输出开头:\n%s", out[:min(len(out), 80)])
	}

	// 每个条目应具备全部基础属性（深度 ≥ 示例）
	for _, attr := range []string{
		"Name=slw-nas\n", "IPv4=127.0.0.1\n", "IPv6=fe80::265e:beff:fe69:a313\n",
		"Hostname=slw-nas.local\n", "TTL=10\n",
	} {
		if !strings.Contains(out, "    "+attr) {
			t.Errorf("输出缺少属性 %q", strings.TrimSpace(attr))
		}
	}
}

// TestE2EJSONFormat 验收：JSON 结构化输出。
func TestE2EJSONFormat(t *testing.T) {
	code, out := runE2E(t, "127.0.0.1")
	if code != 0 {
		t.Fatalf("退出码 %d", code)
	}
	var got struct {
		Assets []struct {
			IP     string `json:"ip"`
			Port   int    `json:"port"`
			Host   string `json:"host"`
			Banner struct {
				Services map[string]struct {
					Name     string   `json:"name"`
					IPv4     []string `json:"ipv4"`
					IPv6     []string `json:"ipv6"`
					Hostname string   `json:"hostname"`
					TTL      uint32   `json:"ttl"`
					TXT      []struct {
						Key   string `json:"key"`
						Value string `json:"value"`
					} `json:"txt"`
				} `json:"services"`
				PTRAnswers []string `json:"ptr_answers"`
			} `json:"banner"`
		} `json:"assets"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("JSON 解析失败: %v\n%s", err, out)
	}
	if len(got.Assets) != 1 {
		t.Fatalf("期望 1 个资产，实际 %d", len(got.Assets))
	}
	a := got.Assets[0]
	if a.IP != "127.0.0.1" || a.Host != "slw-nas.local" || a.Port == 0 {
		t.Errorf("资产基础字段错误: ip=%s port=%d host=%s", a.IP, a.Port, a.Host)
	}

	wantServices := map[string]int{ // key → TXT 项数
		"9/tcp workstation":  0,
		"5000/tcp http":      1,
		"445/tcp smb":        0,
		"5000/tcp qdiscover": 6,
		"device-info":        1,
		"548/tcp afpovertcp": 0,
	}
	if len(a.Banner.Services) != len(wantServices) {
		t.Errorf("期望 %d 个服务，实际 %d: %v", len(wantServices), len(a.Banner.Services), keysOf(a.Banner.Services))
	}
	for k, wantTXT := range wantServices {
		svc, ok := a.Banner.Services[k]
		if !ok {
			t.Errorf("缺少服务 %q", k)
			continue
		}
		if len(svc.TXT) != wantTXT {
			t.Errorf("服务 %q TXT 项数 %d ≠ %d", k, len(svc.TXT), wantTXT)
		}
		if svc.Hostname != "slw-nas.local" || svc.TTL != 10 {
			t.Errorf("服务 %q Hostname/TTL 错误: %q/%d", k, svc.Hostname, svc.TTL)
		}
		if len(svc.IPv4) != 1 || svc.IPv4[0] != "127.0.0.1" {
			t.Errorf("服务 %q IPv4 错误: %v", k, svc.IPv4)
		}
		if len(svc.IPv6) != 1 || svc.IPv6[0] != "fe80::265e:beff:fe69:a313" {
			t.Errorf("服务 %q IPv6 错误: %v", k, svc.IPv6)
		}
	}
	if len(a.Banner.PTRAnswers) != 6 {
		t.Errorf("ptr_answers 期望 6 项，实际 %v", a.Banner.PTRAnswers)
	}

	// 深度抽查：qdiscover TXT 键值
	qd := a.Banner.Services["5000/tcp qdiscover"]
	if len(qd.TXT) == 6 {
		kv := map[string]string{}
		for _, x := range qd.TXT {
			kv[x.Key] = x.Value
		}
		for k, v := range map[string]string{
			"accessType": "https", "accessPort": "86", "model": "TS-X64",
			"displayModel": "TS-464C", "fwVer": "5.2.9", "fwBuildNum": "20260214",
		} {
			if kv[k] != v {
				t.Errorf("qdiscover TXT[%s] = %q ≠ %q", k, kv[k], v)
			}
		}
	}
}

// TestE2EPortRange 验收：端口范围输入（范围中含 fake 端口与死端口）。
func TestE2EPortRange(t *testing.T) {
	r, err := mdnstest.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	p := r.Addr().Port

	// 用宽端口范围（fake 端口前后各 2 个死端口）
	spec := fmt.Sprintf("%d-%d", p-2, p+2)
	var out, errBuf bytes.Buffer
	code := run(context.Background(), []string{"-p", spec, "-c", "16", "-timeout", "600ms", "127.0.0.1"}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("退出码 %d", code)
	}
	var got struct {
		Assets []struct {
			Port int `json:"port"`
		} `json:"assets"`
	}
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Assets) != 1 || got.Assets[0].Port != p {
		t.Errorf("端口范围扫描应只命中 fake 端口 %d，实际 %+v", p, got.Assets)
	}
}

func keysOf[M ~map[string]V, V any](m M) []string {
	var ks []string
	for k := range m {
		ks = append(ks, k)
	}
	return ks
}

// TestE2ENoAssets 验收：无资产的端口返回空列表、退出码 0。
func TestE2ENoAssets(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := run(context.Background(), []string{"-p", "1", "-timeout", "300ms", "127.0.0.1"}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("无资产应退出码 0，实际 %d", code)
	}
	if !strings.Contains(out.String(), `"assets": []`) && !strings.Contains(out.String(), `"assets":[]`) {
		t.Errorf("应输出空资产列表，实际:\n%s", out.String())
	}
}

// TestE2EInvalidArgs 参数校验。
func TestE2EInvalidArgs(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"无参数", nil},
		{"无效格式", []string{"-f", "yaml", "127.0.0.1"}},
		{"无效CIDR", []string{"300.1.1.1/24"}},
		{"无效端口", []string{"-p", "abc", "127.0.0.1"}},
	}
	for _, tt := range tests {
		var out, errBuf bytes.Buffer
		code := run(context.Background(), tt.args, &out, &errBuf)
		if code != 2 {
			t.Errorf("%s: 期望退出码 2，实际 %d", tt.name, code)
		}
	}
}

// TestE2EJSONL 验收：JSONL 流式输出。
func TestE2EJSONL(t *testing.T) {
	code, out := runE2E(t, "--jsonl", "127.0.0.1")
	if code != 0 {
		t.Fatalf("退出码 %d", code)
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 1 {
		t.Fatalf("期望 1 行 JSONL，实际 %d", len(lines))
	}
	if !strings.Contains(lines[0], `"ip":"127.0.0.1"`) || !strings.Contains(lines[0], `"host":"slw-nas.local"`) {
		t.Errorf("JSONL 内容错误: %s", lines[0])
	}
}
