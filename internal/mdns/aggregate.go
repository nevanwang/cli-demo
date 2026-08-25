package mdns

import (
	"fmt"
	"sort"
	"strings"

	"github.com/miekg/dns"
)

// ServiceEntry 是 banner 中单个服务条目的深度属性（对应示例中的
// Name/IPv4/IPv6/Hostname/TTL 及 TXT 深度键值对）。
type ServiceEntry struct {
	Name     string   `json:"name,omitempty"`
	IPv4     []string `json:"ipv4,omitempty"`
	IPv6     []string `json:"ipv6,omitempty"`
	Hostname string   `json:"hostname,omitempty"`
	TTL      uint32   `json:"ttl,omitempty"`
	TXT      []KV     `json:"txt,omitempty"`
}

// Banner 是一个 mDNS 资产的深度识别结果：
//
//	Services:   key = "<SRV端口>/<proto> <服务短名>"（如 "5000/tcp http"）；
//	            无 SRV 记录的服务直接用短名（如 "device-info"）
//	PTRAnswers: 响应中出现过的服务类型 PTR 记录名（去重）
type Banner struct {
	Services   map[string]*ServiceEntry `json:"services"`
	PTRAnswers []string                 `json:"ptr_answers,omitempty"`
}

// Aggregate 将记录池（多轮响应合并）聚合为 banner。
//
// 聚合流程：
//
//	PTR   ──▶ 服务类型 / 实例归属（实例 FQDN → svcType）/ ptr_answers
//	SRV   ──▶ 端口（key 前缀）/ 主机名
//	TXT   ──▶ 深度键值对
//	A/AAAA ─▶ 按主机名分组的地址池
//	回填   ──▶ 无 SRV 的条目复用唯一主机名（单设备场景）及其地址
func Aggregate(records []Record) *Banner {
	records = DedupeRecords(records)
	b := &Banner{Services: map[string]*ServiceEntry{}}

	type instInfo struct {
		svcType string
		entry   *ServiceEntry
		port    uint16
	}
	instances := map[string]*instInfo{}
	var order []string
	ptrSet := map[string]bool{}

	getOrCreate := func(inst, svcType string) *instInfo {
		if info, ok := instances[inst]; ok {
			return info
		}
		info := &instInfo{svcType: svcType, entry: &ServiceEntry{}}
		info.entry.Name = instanceLabel(inst, svcType)
		info.entry.TTL = 0
		instances[inst] = info
		order = append(order, inst)
		return info
	}

	// Pass 1: PTR —— 服务类型、实例归属、ptr_answers
	for _, r := range records {
		if r.Type != "PTR" {
			continue
		}
		if strings.EqualFold(r.Name, EnumName) {
			continue // 枚举 PTR：rdata 是服务类型，不产生条目
		}
		ptrSet[r.Name] = true
		if r.Target == "" {
			continue
		}
		info := getOrCreate(r.Target, r.Name)
		info.entry.mergeTTL(r.TTL)
	}

	// Pass 2: SRV/TXT —— 处理 additional 段直接出现、无对应 PTR 的实例
	for _, r := range records {
		if r.Type != "SRV" && r.Type != "TXT" {
			continue
		}
		if _, ok := instances[r.Name]; ok {
			continue
		}
		svc := inferServiceType(r.Name)
		if svc == "" {
			continue // 名称结构不是服务实例（如主机名上挂的记录）
		}
		getOrCreate(r.Name, svc)
	}

	// Pass 3: 填充 SRV / TXT / TTL
	for _, r := range records {
		switch r.Type {
		case "SRV":
			if info, ok := instances[r.Name]; ok {
				info.port = r.Port
				info.entry.Hostname = strings.TrimSuffix(r.Target, ".")
				info.entry.mergeTTL(r.TTL)
			}
		case "TXT":
			if info, ok := instances[r.Name]; ok {
				info.entry.TXT = r.TXT
				info.entry.mergeTTL(r.TTL)
			}
		case "PTR":
			if !strings.EqualFold(r.Name, EnumName) {
				if info, ok := instances[r.Target]; ok {
					info.entry.mergeTTL(r.TTL)
				}
			}
		}
	}

	// Pass 4: A/AAAA 按名称分组；收集主机名集合
	type addrs struct{ v4, v6 []string }
	addrByName := map[string]*addrs{}
	hostnames := map[string]bool{}
	appendAddr := func(name, ip string, v4 bool) {
		a := addrByName[name]
		if a == nil {
			a = &addrs{}
			addrByName[name] = a
		}
		if v4 {
			a.v4 = appendUnique(a.v4, ip)
		} else {
			a.v6 = appendUnique(a.v6, ip)
		}
	}
	for _, r := range records {
		switch r.Type {
		case "A":
			appendAddr(r.Name, r.IP, true)
			hostnames[r.Name] = true
		case "AAAA":
			appendAddr(r.Name, r.IP, false)
			hostnames[r.Name] = true
		case "SRV":
			hostnames[r.Target] = true
		}
	}
	uniqueHost := ""
	if len(hostnames) == 1 {
		for h := range hostnames {
			uniqueHost = h
		}
	}

	// Pass 5: 回填 Hostname / IPv4 / IPv6
	for _, inst := range order {
		info := instances[inst]
		e := info.entry
		if e.Hostname == "" && uniqueHost != "" {
			e.Hostname = strings.TrimSuffix(uniqueHost, ".")
		}
		if a := addrByName[uniqueHostKey(e.Hostname)]; a != nil {
			e.IPv4 = appendUnique(e.IPv4, a.v4...)
			e.IPv6 = appendUnique(e.IPv6, a.v6...)
		}
	}

	// Pass 6: 生成 key（确定性顺序）
	for _, inst := range order {
		info := instances[inst]
		short, proto := splitServiceType(info.svcType)
		if short == "" {
			continue
		}
		key := short
		if info.port > 0 {
			key = fmt.Sprintf("%d/%s %s", info.port, proto, short)
		}
		if _, exists := b.Services[key]; exists {
			// 同 key 多实例（同服务多实例同端口）：加序号区分
			for i := 2; ; i++ {
				alt := fmt.Sprintf("%s #%d", key, i)
				if _, exists := b.Services[alt]; !exists {
					key = alt
					break
				}
			}
		}
		b.Services[key] = info.entry
	}

	for p := range ptrSet {
		b.PTRAnswers = append(b.PTRAnswers, strings.TrimSuffix(p, "."))
	}
	sort.Strings(b.PTRAnswers)
	return b
}

// PrimaryHost 返回 banner 的主主机名：优先唯一主机名，
// 否则取按服务 key 排序后的第一个非空 Hostname，最后回退 "local" 域外推。
func (b *Banner) PrimaryHost() string {
	hosts := map[string]bool{}
	keys := make([]string, 0, len(b.Services))
	for k := range b.Services {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if h := b.Services[k].Hostname; h != "" {
			hosts[h] = true
		}
	}
	if len(hosts) == 1 {
		for h := range hosts {
			return h
		}
	}
	for _, k := range keys {
		if h := b.Services[k].Hostname; h != "" {
			return h
		}
	}
	return ""
}

// mergeTTL 取较小的 TTL 作为条目 TTL（模拟缓存视角）。
func (e *ServiceEntry) mergeTTL(ttl uint32) {
	if ttl == 0 {
		return
	}
	if e.TTL == 0 || ttl < e.TTL {
		e.TTL = ttl
	}
}

// instanceLabel 从实例 FQDN 提取服务类型之外的实例标签。
// 例: inst="slw-nas [24:5e:be:69:a3:13]._workstation._tcp.local." svc="_workstation._tcp.local."
//
//	→ "slw-nas [24:5e:be:69:a3:13]"
func instanceLabel(inst, svc string) string {
	i := strings.TrimSuffix(inst, ".")
	s := strings.TrimSuffix(svc, ".")
	if i == s {
		return ""
	}
	if strings.HasSuffix(i, "."+s) {
		return strings.TrimSuffix(i, "."+s)
	}
	return i
}

// inferServiceType 从实例 FQDN 尾部推断服务类型。
// 仅接受形如 "<label>._<svc>._tcp|_udp.local." 的名称，否则返回空串。
func inferServiceType(inst string) string {
	labels := dns.SplitDomainName(inst)
	n := len(labels)
	if n < 3 {
		return ""
	}
	tld := labels[n-1]
	proto := labels[n-2]
	svcName := labels[n-3]
	if tld != "local" || (proto != "_tcp" && proto != "_udp") || !strings.HasPrefix(svcName, "_") {
		return ""
	}
	return svcName + "." + proto + "." + tld + "."
}

// splitServiceType 将服务类型 FQDN 拆为（短名, 协议）。
// 例: "_workstation._tcp.local." → ("workstation", "tcp")
func splitServiceType(svc string) (short, proto string) {
	labels := dns.SplitDomainName(svc)
	n := len(labels)
	if n < 2 {
		return "", ""
	}
	proto = strings.TrimPrefix(labels[n-2], "_")
	parts := make([]string, 0, n-2)
	for _, l := range labels[:n-2] {
		parts = append(parts, strings.TrimPrefix(l, "_"))
	}
	short = strings.Join(parts, ".")
	if labels[n-1] != "local" {
		short += "." + labels[n-1]
	}
	return short, proto
}

// uniqueHostKey 将无尾点的主机名归一化为 addrByName 的键（记录名均带尾点）。
func uniqueHostKey(host string) string {
	if host == "" {
		return ""
	}
	return strings.TrimSuffix(host, ".") + "."
}

func appendUnique(dst []string, vals ...string) []string {
	for _, v := range vals {
		if v == "" {
			continue
		}
		dup := false
		for _, d := range dst {
			if d == v {
				dup = true
				break
			}
		}
		if !dup {
			dst = append(dst, v)
		}
	}
	return dst
}
