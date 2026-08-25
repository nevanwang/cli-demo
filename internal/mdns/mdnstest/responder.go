// Package mdnstest 提供可编程的 fake mDNS 响应者，用于离线验证扫描器。
//
// 默认服务集复刻任务示例中的 slw-nas NAS（威联通 TS-464C）：
// 6 个服务 + 深度 TXT 字段 + A/AAAA 记录，TTL 统一为 10。
package mdnstest

import (
	"net"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

// HostName 是 fake 设备的主机名。
const HostName = "slw-nas.local."

// HostIPv6 是 fake 设备的 AAAA 记录值（与任务示例一致）。
const HostIPv6 = "fe80::265e:beff:fe69:a313"

// TTL 是所有 fake 记录的统一 TTL。
const TTL = 10

// cacheFlush 返回带 cache-flush bit 的 class（模拟真实 mDNS 记录）。
const cacheFlushClass = dns.ClassINET | 0x8000

type instDef struct {
	label   string   // 实例标签（不含服务类型部分）
	srvPort uint16   // 0 = 无 SRV 记录（如 device-info）
	txt     []string // TXT 条目
}

func (i instDef) fqdn(svcType string) string {
	return i.label + "." + svcType
}

type svcDef struct {
	svcType   string
	instances []instDef
}

// services 复刻任务示例中的 slw-nas NAS。
var services = []svcDef{
	{svcType: "_workstation._tcp.local.", instances: []instDef{
		{label: "slw-nas [24:5e:be:69:a3:13]", srvPort: 9},
	}},
	{svcType: "_http._tcp.local.", instances: []instDef{
		{label: "slw-nas", srvPort: 5000, txt: []string{"path=/"}},
	}},
	{svcType: "_smb._tcp.local.", instances: []instDef{
		{label: "slw-nas", srvPort: 445},
	}},
	{svcType: "_qdiscover._tcp.local.", instances: []instDef{
		{label: "slw-nas", srvPort: 5000, txt: []string{
			"accessType=https",
			"accessPort=86",
			"model=TS-X64",
			"displayModel=TS-464C",
			"fwVer=5.2.9",
			"fwBuildNum=20260214",
		}},
	}},
	{svcType: "_device-info._tcp.local.", instances: []instDef{
		{label: "slw-nas(AFP)", txt: []string{"model=Xserve"}}, // 无 SRV
	}},
	{svcType: "_afpovertcp._tcp.local.", instances: []instDef{
		{label: "slw-nas(AFP)", srvPort: 548},
	}},
}

// Responder 是监听在指定 UDP 地址上的 fake mDNS 响应者。
type Responder struct {
	conn   *net.UDPConn
	hostIP net.IP
	done   chan struct{}
	wg     sync.WaitGroup
}

// Start 在 127.0.0.1 的随机可用 UDP 端口启动响应者。
func Start() (*Responder, error) {
	return StartAddr("127.0.0.1:0")
}

// StartAddr 在指定地址启动响应者（地址需含端口，0 表示随机）。
func StartAddr(addr string) (*Responder, error) {
	ua, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp4", ua)
	if err != nil {
		return nil, err
	}
	hostIP := conn.LocalAddr().(*net.UDPAddr).IP
	if hostIP == nil || hostIP.IsUnspecified() {
		hostIP = net.IPv4(127, 0, 0, 1)
	}
	r := &Responder{conn: conn, hostIP: hostIP, done: make(chan struct{})}
	r.wg.Add(1)
	go r.serve()
	return r, nil
}

// Addr 返回实际监听地址。
func (r *Responder) Addr() *net.UDPAddr {
	return r.conn.LocalAddr().(*net.UDPAddr)
}

// Close 停止响应者。
func (r *Responder) Close() error {
	close(r.done)
	err := r.conn.Close()
	r.wg.Wait()
	return err
}

func (r *Responder) serve() {
	defer r.wg.Done()
	buf := make([]byte, 9000)
	for {
		n, remote, err := r.conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-r.done:
				return
			default:
				continue
			}
		}
		var req dns.Msg
		if err := req.Unpack(buf[:n]); err != nil {
			continue
		}
		if req.Response {
			continue // 忽略响应包（可能是其他扫描器）
		}
		resp := r.buildResponse(&req)
		if resp == nil {
			continue
		}
		wire, err := resp.Pack()
		if err != nil {
			continue
		}
		if _, err := r.conn.WriteToUDP(wire, remote); err != nil {
			return
		}
	}
}

// buildResponse 依据请求的 question 生成响应（answer 段 + additional 段，
// 模拟 avahi/mDNSResponder 的典型行为：additional 段携带 SRV/TXT/A/AAAA）。
func (r *Responder) buildResponse(req *dns.Msg) *dns.Msg {
	resp := new(dns.Msg)
	resp.Id = req.Id
	resp.Response = true
	resp.Authoritative = true
	resp.Compress = true // 测试压缩指针解析

	seen := map[string]bool{}
	addAnswer := func(rr dns.RR) {
		k := rr.String()
		if !seen[k] {
			seen[k] = true
			resp.Answer = append(resp.Answer, rr)
		}
	}
	addExtra := func(rr dns.RR) {
		k := rr.String()
		if !seen[k] {
			seen[k] = true
			resp.Extra = append(resp.Extra, rr)
		}
	}

	appendInstanceRecords := func(svc svcDef, inst instDef) {
		instFQDN := inst.fqdn(svc.svcType)
		if inst.srvPort > 0 {
			addExtra(newSRV(instFQDN, inst.srvPort, HostName))
			addExtra(newA(HostName, r.hostIP))
			addExtra(newAAAA(HostName, HostIPv6))
		}
		if len(inst.txt) > 0 {
			addExtra(newTXT(instFQDN, inst.txt))
		}
	}

	for _, q := range req.Question {
		name := strings.ToLower(q.Name)
		switch q.Qtype {
		case dns.TypePTR:
			if name == "_services._dns-sd._udp.local." {
				for _, svc := range services {
					addAnswer(newPTR("_services._dns-sd._udp.local.", svc.svcType))
					// 枚举响应的 additional 段带各服务首个实例记录（减少深挖往返）
					appendInstanceRecords(svc, svc.instances[0])
				}
				continue
			}
			if svc := findService(name); svc != nil {
				for _, inst := range svc.instances {
					addAnswer(newPTR(svc.svcType, inst.fqdn(svc.svcType)))
					appendInstanceRecords(*svc, inst)
				}
			}
		case dns.TypeSRV:
			if inst, svc := findInstance(name); inst != nil && inst.srvPort > 0 {
				addAnswer(newSRV(inst.fqdn(svc.svcType), inst.srvPort, HostName))
				addExtra(newA(HostName, r.hostIP))
				addExtra(newAAAA(HostName, HostIPv6))
			}
		case dns.TypeTXT:
			if inst, svc := findInstance(name); inst != nil && len(inst.txt) > 0 {
				addAnswer(newTXT(inst.fqdn(svc.svcType), inst.txt))
			}
		case dns.TypeA:
			if name == HostName {
				addAnswer(newA(HostName, r.hostIP))
			}
		case dns.TypeAAAA:
			if name == HostName {
				addAnswer(newAAAA(HostName, HostIPv6))
			}
		}
	}

	if len(resp.Answer) == 0 {
		return nil
	}
	return resp
}

func findService(name string) *svcDef {
	for i := range services {
		if strings.EqualFold(services[i].svcType, name) {
			return &services[i]
		}
	}
	return nil
}

func findInstance(name string) (*instDef, *svcDef) {
	for i := range services {
		for j := range services[i].instances {
			if strings.EqualFold(services[i].instances[j].fqdn(services[i].svcType), name) {
				return &services[i].instances[j], &services[i]
			}
		}
	}
	return nil, nil
}

func newPTR(name, ptr string) *dns.PTR {
	return &dns.PTR{
		Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypePTR, Class: cacheFlushClass, Ttl: TTL},
		Ptr: ptr,
	}
}

func newSRV(name string, port uint16, target string) *dns.SRV {
	return &dns.SRV{
		Hdr:      dns.RR_Header{Name: name, Rrtype: dns.TypeSRV, Class: cacheFlushClass, Ttl: TTL},
		Priority: 0,
		Weight:   0,
		Port:     port,
		Target:   target,
	}
}

func newTXT(name string, items []string) *dns.TXT {
	return &dns.TXT{
		Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: cacheFlushClass, Ttl: TTL},
		Txt: items,
	}
}

func newA(name string, ip net.IP) *dns.A {
	return &dns.A{
		Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: cacheFlushClass, Ttl: TTL},
		A:   ip.To4(),
	}
}

func newAAAA(name, ip string) *dns.AAAA {
	return &dns.AAAA{
		Hdr:  dns.RR_Header{Name: name, Rrtype: dns.TypeAAAA, Class: cacheFlushClass, Ttl: TTL},
		AAAA: net.ParseIP(ip),
	}
}
