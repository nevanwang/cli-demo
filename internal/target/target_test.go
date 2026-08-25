package target

import (
	"net"
	"strings"
	"testing"
)

func TestParseCIDR(t *testing.T) {
	tests := []struct {
		in      string
		wantIPs int64 // Count 结果
		wantErr bool
	}{
		{in: "192.168.1.0/24", wantIPs: 254},
		{in: "192.168.1.5", wantIPs: 1},
		{in: "10.0.0.0/8", wantIPs: (1 << 24) - 2},
		{in: "10.0.0.0/31", wantIPs: 2},
		{in: "10.0.0.4/32", wantIPs: 1},
		{in: "fe80::/64", wantIPs: 1 << 62}, // 溢出保护
		{in: "::1/128", wantIPs: 1},
		{in: "", wantErr: true},
		{in: "192.168.1.256", wantErr: true},
		{in: "192.168.1.0/33", wantErr: true},
		{in: "abc", wantErr: true},
	}
	for _, tt := range tests {
		ipnet, err := ParseCIDR(tt.in)
		if tt.wantErr {
			if err == nil {
				t.Errorf("ParseCIDR(%q) 期望报错，实际成功", tt.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseCIDR(%q) 意外报错: %v", tt.in, err)
			continue
		}
		if got := Count(ipnet); got != tt.wantIPs {
			t.Errorf("ParseCIDR(%q).Count = %d, 期望 %d", tt.in, got, tt.wantIPs)
		}
	}
}

func TestParsePorts(t *testing.T) {
	tests := []struct {
		in      string
		want    []int
		wantErr bool
	}{
		{in: "5353", want: []int{5353}},
		{in: "5350-5353", want: []int{5350, 5351, 5352, 5353}},
		{in: "5353,80", want: []int{80, 5353}},
		{in: "5353,5351-5352", want: []int{5351, 5352, 5353}},
		{in: "5353,5353", want: []int{5353}}, // 去重
		{in: "5353-5350", wantErr: true},     // 起始大于结束
		{in: "0", wantErr: true},
		{in: "65536", wantErr: true},
		{in: "abc", wantErr: true},
		{in: "", wantErr: true},
		{in: ",", wantErr: true},
	}
	for _, tt := range tests {
		got, err := ParsePorts(tt.in)
		if tt.wantErr {
			if err == nil {
				t.Errorf("ParsePorts(%q) 期望报错，实际 %v", tt.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParsePorts(%q) 意外报错: %v", tt.in, err)
			continue
		}
		if len(got) != len(tt.want) {
			t.Errorf("ParsePorts(%q) = %v, 期望 %v", tt.in, got, tt.want)
			continue
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("ParsePorts(%q) = %v, 期望 %v", tt.in, got, tt.want)
				break
			}
		}
	}
}

func TestBuildTargets(t *testing.T) {
	// /29 = 8 地址，排除网络+广播 = 6 主机
	ipnet, err := ParseCIDR("192.168.1.0/29")
	if err != nil {
		t.Fatal(err)
	}
	ports := []int{5353}
	targets, err := BuildTargets(ipnet, ports)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 6 {
		t.Fatalf("期望 6 个目标，实际 %d", len(targets))
	}
	first, last := targets[0].IP.String(), targets[5].IP.String()
	if first != "192.168.1.1" || last != "192.168.1.6" {
		t.Errorf("期望首目标 192.168.1.1 末目标 192.168.1.6，实际 %s ~ %s", first, last)
	}
	if targets[0].Addr() != "192.168.1.1:5353" {
		t.Errorf("Addr() = %q", targets[0].Addr())
	}

	// 单 IP 不排除
	ipnet2, _ := ParseCIDR("10.1.2.3")
	targets2, _ := BuildTargets(ipnet2, []int{5353})
	if len(targets2) != 1 || targets2[0].IP.String() != "10.1.2.3" {
		t.Errorf("单 IP 展开错误: %v", targets2)
	}

	// 端口笛卡尔积
	targets3, _ := BuildTargets(ipnet2, []int{5353, 5354})
	if len(targets3) != 2 {
		t.Errorf("期望 2 个目标，实际 %d", len(targets3))
	}
}

func TestListIPsIPv6(t *testing.T) {
	ipnet, err := ParseCIDR("fe80::1/126")
	if err != nil {
		t.Fatal(err)
	}
	ips, err := ListIPs(ipnet, Count(ipnet))
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 4 {
		t.Fatalf("期望 4 个 IPv6，实际 %d", len(ips))
	}
	if ips[0].String() != "fe80::" || ips[3].String() != "fe80::3" {
		var strs []string
		for _, ip := range ips {
			strs = append(strs, ip.String())
		}
		t.Errorf("IPv6 展开错误: %s", strings.Join(strs, ","))
	}
}

func TestEachIPOverflow(t *testing.T) {
	// 超大网段 + 有限 count：只回调 count 次
	_, ipnet, _ := net.ParseCIDR("10.0.0.0/8")
	calls := 0
	err := EachIP(ipnet, 3, func(net.IP) error {
		calls++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 3 {
		t.Errorf("期望 3 次回调，实际 %d", calls)
	}
}
