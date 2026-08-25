package mdns

import (
	"strings"

	"github.com/miekg/dns"
)

const (
	// EnumName 是 DNS-SD 服务类型枚举查询名（RFC 6763 §9）。
	EnumName = "_services._dns-sd._udp.local."
	// MulticastGroup4 是 mDNS IPv4 组播地址。
	MulticastGroup4 = "224.0.0.251"
	// MDNSPort 是 mDNS 标准端口。
	MDNSPort = 5353
)

// queryClassQU = IN | QU bit（RFC 6762 §5.4，要求响应者单播回包）。
const queryClassQU = dns.ClassINET | 0x8000

// CommonServiceTypes 是识别轮的常见服务类型字典。
// 嵌入式设备常不响应枚举查询但会响应具体类型的 PTR 查询，字典用于兜底。
var CommonServiceTypes = []string{
	"_http._tcp.local.",
	"_https._tcp.local.",
	"_smb._tcp.local.",
	"_workstation._tcp.local.",
	"_device-info._tcp.local.",
	"_afpovertcp._tcp.local.",
	"_airplay._tcp.local.",
	"_raop._tcp.local.",
	"_googlecast._tcp.local.",
	"_hap._tcp.local.",
	"_ipp._tcp.local.",
	"_printer._tcp.local.",
	"_ssh._tcp.local.",
	"_ftp._tcp.local.",
	"_nfs._tcp.local.",
	"_webdav._tcp.local.",
	"_sftp-ssh._tcp.local.",
	"_uscan._tcp.local.",
	"_companion-link._tcp.local.",
	"_touch-able._tcp.local.",
}

// MaxFollowUpQueries 是单资产深挖轮的查询数上限，防恶意响应导致查询风暴放大。
const MaxFollowUpQueries = 64

// mdnsQuerySemantics 将报文恢复为 mDNS 查询语义：
// miekg 的 SetQuestion 会写入随机 ID 并置 RD=true，均不符合 RFC 6762。
func mdnsQuerySemantics(m *dns.Msg) *dns.Msg {
	m.Id = 0 // mDNS 查询 ID 固定为 0（RFC 6762 §18.1）
	m.RecursionDesired = false
	return m
}

// BuildPtrQuery 构造带 QU bit 的单条 PTR 查询。
func BuildPtrQuery(name string) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypePTR)
	mdnsQuerySemantics(m)
	m.Question[0].Qclass = queryClassQU
	return m
}

// BuildInstanceQuery 对实例名构造 SRV+TXT 组合查询（同一实例的两条 question）。
func BuildInstanceQuery(instance string) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(instance), dns.TypeSRV)
	m.Question[0].Qclass = queryClassQU
	m.Question = append(m.Question, dns.Question{
		Name:   dns.Fqdn(instance),
		Qtype:  dns.TypeTXT,
		Qclass: queryClassQU,
	})
	mdnsQuerySemantics(m)
	return m
}

// BuildHostQuery 对主机名构造 A+AAAA 组合查询。
func BuildHostQuery(host string) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(host), dns.TypeA)
	m.Question[0].Qclass = queryClassQU
	m.Question = append(m.Question, dns.Question{
		Name:   dns.Fqdn(host),
		Qtype:  dns.TypeAAAA,
		Qclass: queryClassQU,
	})
	mdnsQuerySemantics(m)
	return m
}

// ProbeQueries 返回识别轮全部探针：服务类型枚举 + 常见类型字典。
func ProbeQueries() []*dns.Msg {
	qs := make([]*dns.Msg, 0, 1+len(CommonServiceTypes))
	qs = append(qs, BuildPtrQuery(EnumName))
	for _, svc := range CommonServiceTypes {
		qs = append(qs, BuildPtrQuery(svc))
	}
	return qs
}

// FollowUpQueries 依据已收集的记录生成深挖轮查询（只补查缺失项）：
//
//	枚举发现但无实例 PTR 的服务类型 → PTR <svcType>
//	缺 SRV 或 TXT 的实例           → SRV+TXT <instance>
//	缺 A/AAAA 的主机名             → A+AAAA <host>
//
// 所有名称均来自响应（不可信输入），构造前用 SafeQueryName 校验。
func FollowUpQueries(records []Record, maxQueries int) []Record2Query {
	if maxQueries <= 0 {
		maxQueries = MaxFollowUpQueries
	}
	summary := summarize(records)

	var qs []Record2Query
	for _, svc := range summary.svcTypes {
		if !summary.hasInstancePTR[svc] {
			qs = append(qs, Record2Query{Kind: QueryKindPTR, Name: svc})
		}
	}
	for _, inst := range summary.instances {
		if !summary.hasSRV[inst] || !summary.hasTXT[inst] {
			qs = append(qs, Record2Query{Kind: QueryKindInstance, Name: inst})
		}
	}
	for _, host := range summary.hosts {
		if !summary.hasAddr[host] {
			qs = append(qs, Record2Query{Kind: QueryKindHost, Name: host})
		}
	}
	if len(qs) > maxQueries {
		qs = qs[:maxQueries]
	}
	return qs
}

// QueryKind 标识深挖查询类型。
type QueryKind int

const (
	// QueryKindPTR 服务类型 PTR 查询。
	QueryKindPTR QueryKind = iota
	// QueryKindInstance 实例 SRV+TXT 查询。
	QueryKindInstance
	// QueryKindHost 主机名 A+AAAA 查询。
	QueryKindHost
)

// Record2Query 是深挖轮的一条待发查询。
type Record2Query struct {
	Kind QueryKind
	Name string
}

// Build 将其转换为 DNS 查询报文。
func (q Record2Query) Build() *dns.Msg {
	switch q.Kind {
	case QueryKindInstance:
		return BuildInstanceQuery(q.Name)
	case QueryKindHost:
		return BuildHostQuery(q.Name)
	default:
		return BuildPtrQuery(q.Name)
	}
}

type recordSummary struct {
	svcTypes       []string
	instances      []string
	hosts          []string
	hasInstancePTR map[string]bool // svcType → 已有实例 PTR 记录
	hasSRV         map[string]bool // instance → 已有 SRV
	hasTXT         map[string]bool // instance → 已有 TXT
	hasAddr        map[string]bool // host → 已有 A 或 AAAA
}

func summarize(records []Record) *recordSummary {
	s := &recordSummary{
		hasInstancePTR: map[string]bool{},
		hasSRV:         map[string]bool{},
		hasTXT:         map[string]bool{},
		hasAddr:        map[string]bool{},
	}
	seenSvc := map[string]bool{}
	seenInst := map[string]bool{}
	seenHost := map[string]bool{}

	addSvc := func(name string) {
		if name != "" && !seenSvc[name] {
			seenSvc[name] = true
			s.svcTypes = append(s.svcTypes, name)
		}
	}
	addInst := func(name string) {
		if name != "" && !seenInst[name] {
			seenInst[name] = true
			s.instances = append(s.instances, name)
		}
	}
	addHost := func(name string) {
		if name != "" && !seenHost[name] {
			seenHost[name] = true
			s.hosts = append(s.hosts, name)
		}
	}

	for _, r := range records {
		switch r.Type {
		case "PTR":
			if strings.EqualFold(r.Name, EnumName) {
				// 枚举响应：rdata 是服务类型
				if SafeQueryName(r.Target) {
					addSvc(r.Target)
				}
			} else {
				if SafeQueryName(r.Name) {
					addSvc(r.Name)
					s.hasInstancePTR[r.Name] = true
				}
				if SafeQueryName(r.Target) {
					addInst(r.Target)
				}
			}
		case "SRV":
			if SafeQueryName(r.Name) {
				s.hasSRV[r.Name] = true
				addInst(r.Name)
			}
			if SafeQueryName(r.Target) {
				addHost(r.Target)
			}
		case "TXT":
			if SafeQueryName(r.Name) {
				s.hasTXT[r.Name] = true
				addInst(r.Name)
			}
		case "A", "AAAA":
			if SafeQueryName(r.Name) {
				s.hasAddr[r.Name] = true
				addHost(r.Name)
			}
		}
	}
	return s
}

// SafeQueryName 校验来自响应的查询名是否可以安全回查：
// 总长 ≤253、label 数 ≤128、每 label ≤63 且仅含可打印 ASCII。
// 防止恶意响应诱导我们向网络注入垃圾查询（放大攻击面）。
func SafeQueryName(name string) bool {
	if len(name) == 0 || len(name) > 253 {
		return false
	}
	n := strings.TrimSuffix(name, ".")
	labels := strings.Split(n, ".")
	if len(labels) == 0 || len(labels) > 128 {
		return false
	}
	for _, l := range labels {
		if len(l) == 0 || len(l) > 63 {
			return false
		}
		for i := 0; i < len(l); i++ {
			if l[i] < 0x20 || l[i] > 0x7E {
				return false
			}
		}
	}
	return true
}
