// Package target 负责 CIDR 网段与端口范围的解析与展开。
//
// 数据流：
//
//	CIDR 字符串 ──ParseCIDR──▶ *net.IPNet ─┐
//	                                        ├─BuildTargets──▶ []Target{(ip,port)}
//	端口规格字符串 ─ParsePorts──▶ []int ───┘
package target

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
)

// Target 表示一个探测目标 (IP, Port)。
type Target struct {
	IP   net.IP
	Port int
}

// Addr 返回 "ip:port" 形式的拨号地址。
func (t Target) Addr() string {
	return net.JoinHostPort(t.IP.String(), strconv.Itoa(t.Port))
}

// ParseCIDR 解析 "192.168.1.0/24" 形式的 CIDR 或 "192.168.1.5" 单 IP。
func ParseCIDR(s string) (*net.IPNet, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("空的网段")
	}
	if strings.Contains(s, "/") {
		_, ipnet, err := net.ParseCIDR(s)
		if err != nil {
			return nil, fmt.Errorf("无效 CIDR %q: %w", s, err)
		}
		return ipnet, nil
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return nil, fmt.Errorf("无效 IP %q", s)
	}
	bits := 128
	if ip.To4() != nil {
		bits = 32
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}, nil
}

// ParsePorts 解析端口规格："5353"、"5350-5360"、"5353,8000-8010"（逗号分隔组合），
// 返回升序去重后的端口列表。
func ParsePorts(spec string) ([]int, error) {
	var ports []int
	seen := map[int]bool{}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		lo, hi, err := parsePortRange(part)
		if err != nil {
			return nil, err
		}
		for p := lo; p <= hi; p++ {
			if !seen[p] {
				seen[p] = true
				ports = append(ports, p)
			}
		}
	}
	if len(ports) == 0 {
		return nil, fmt.Errorf("端口规格 %q 未包含任何端口", spec)
	}
	sort.Ints(ports)
	return ports, nil
}

func parsePortRange(s string) (lo, hi int, err error) {
	if i := strings.IndexByte(s, '-'); i >= 0 {
		lo, err = parsePort(s[:i])
		if err != nil {
			return 0, 0, err
		}
		hi, err = parsePort(s[i+1:])
		if err != nil {
			return 0, 0, err
		}
		if lo > hi {
			return 0, 0, fmt.Errorf("端口范围 %q 起始大于结束", s)
		}
		return lo, hi, nil
	}
	p, err := parsePort(s)
	if err != nil {
		return 0, 0, err
	}
	return p, p, nil
}

func parsePort(s string) (int, error) {
	p, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || p < 1 || p > 65535 {
		return 0, fmt.Errorf("无效端口 %q（需 1-65535）", s)
	}
	return p, nil
}

// Count 返回网段内可探测 IP 数。
// IPv4 前缀长度 ≤30 时排除网络地址与广播地址；单 IP（/32、/128）全保留。
// 溢出时返回 math.MaxInt64。
func Count(ipnet *net.IPNet) int64 {
	ones, bits := ipnet.Mask.Size()
	if bits == 0 {
		return 0
	}
	hostBits := bits - ones
	if hostBits >= 63 {
		return int64(1) << 62
	}
	n := int64(1) << uint(hostBits)
	if ipnet.IP.To4() != nil && ones <= 30 {
		n -= 2
	}
	if n <= 0 {
		return 0
	}
	return n
}

// ListIPs 展开网段内全部可探测 IP。
// count 为期望数量上限（由调用方依据 Count 计算并校验后传入，防止巨型网段撑爆内存）。
func ListIPs(ipnet *net.IPNet, count int64) ([]net.IP, error) {
	if count < 0 {
		return nil, fmt.Errorf("目标数为负")
	}
	ips := make([]net.IP, 0, count)
	err := EachIP(ipnet, count, func(ip net.IP) error {
		ips = append(ips, ip)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return ips, nil
}

// EachIP 遍历网段内全部可探测 IP，逐个回调。count 语义同 ListIPs。
func EachIP(ipnet *net.IPNet, count int64, fn func(net.IP) error) error {
	ones, bits := ipnet.Mask.Size()
	if bits == 0 {
		return fmt.Errorf("无效掩码")
	}
	base := ipnet.IP
	if v4 := base.To4(); v4 != nil {
		base = v4
	} else {
		base = base.To16()
	}
	if base == nil {
		return fmt.Errorf("无效网段 IP")
	}
	isV4 := len(base) == 4
	skipEdges := isV4 && ones <= 30

	start := int64(0)
	if skipEdges {
		start = 1 // 跳过网络地址
	}
	var end int64 = count
	if skipEdges {
		// count 已排除两端：遍历 [1, count]，即首地址+1 起，共 count 个
		end = count + 1 // 含边界（闭区间 [start, end-1]）
	}
	for i := start; i < end; i++ {
		ip := ipAdd(base, i)
		if ip == nil {
			return fmt.Errorf("IP 溢出")
		}
		if err := fn(ip); err != nil {
			return err
		}
	}
	return nil
}

// BuildTargets 生成 ipnet × ports 的全部目标组合。
func BuildTargets(ipnet *net.IPNet, ports []int) ([]Target, error) {
	ips, err := ListIPs(ipnet, Count(ipnet))
	if err != nil {
		return nil, err
	}
	targets := make([]Target, 0, len(ips)*len(ports))
	for _, ip := range ips {
		for _, p := range ports {
			targets = append(targets, Target{IP: ip, Port: p})
		}
	}
	return targets, nil
}

// ipAdd 返回 base + n 的新 IP（不修改 base），IPv4 按 32 位、IPv6 按 128 位回绕。
func ipAdd(base net.IP, n int64) net.IP {
	if len(base) == 4 {
		b := uint32(int32(n)) // 允许回绕（n 在网段范围内时不会发生）
		out := make(net.IP, 4)
		v := uint32(base[0])<<24 | uint32(base[1])<<16 | uint32(base[2])<<8 | uint32(base[3])
		v += b
		out[0], out[1], out[2], out[3] = byte(v>>24), byte(v>>16), byte(v>>8), byte(v)
		return out
	}
	if len(base) == 16 {
		hi := uint64(base[0])<<56 | uint64(base[1])<<48 | uint64(base[2])<<40 | uint64(base[3])<<32 |
			uint64(base[4])<<24 | uint64(base[5])<<16 | uint64(base[6])<<8 | uint64(base[7])
		lo := uint64(base[8])<<56 | uint64(base[9])<<48 | uint64(base[10])<<40 | uint64(base[11])<<32 |
			uint64(base[12])<<24 | uint64(base[13])<<16 | uint64(base[14])<<8 | uint64(base[15])
		loNew := lo + uint64(n)
		if loNew < lo && n > 0 {
			hi++
		}
		out := make(net.IP, 16)
		for i := 0; i < 8; i++ {
			out[i] = byte(hi >> uint(56-8*i))
			out[8+i] = byte(loNew >> uint(56-8*i))
		}
		return out
	}
	return nil
}
