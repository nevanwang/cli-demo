// Package mdns 实现 mDNS 探针构造、响应解析与资产 banner 深度聚合。
//
// 管线：
//
//	识别轮探针 ──▶ UDP 响应 ──ParseResponse──▶ []Record ──Aggregate──▶ *Banner
//	     ▲                                          │
//	     └────────── FollowUpQueries（深挖轮） ◀────┘
package mdns

import (
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

// MaxResponseSize 单个 UDP 响应的读取缓冲上限（防恶意超大包）。
const MaxResponseSize = 9000

// KV 表示 TXT 记录中的一个键值对。
type KV struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// Record 表示从 mDNS 响应中提取的一条归一化资源记录。
// 各类型有效字段：
//
//	PTR: Target（rdata，实例名或服务类型）
//	SRV: Target（主机名）、Port
//	TXT: TXT（键值对列表）
//	A/AAAA: IP
type Record struct {
	Name   string // 记录名（FQDN，含尾点），如 "_workstation._tcp.local."
	Type   string // PTR / SRV / TXT / A / AAAA
	TTL    uint32
	Target string
	Port   uint16
	TXT    []KV
	IP     string
}

// ParseResponse 将 UDP 载荷解析为记录列表。
// 返回 false 表示载荷不是可解析的 DNS 响应（查询包、畸形包、无关协议）。
// answer / authority / additional 三段全部收集——mDNS 响应常把 SRV/TXT/A 放在 additional 段。
func ParseResponse(data []byte) ([]Record, bool) {
	if len(data) < 12 {
		return nil, false
	}
	var msg dns.Msg
	if err := msg.Unpack(data); err != nil {
		return nil, false
	}
	if !msg.Response {
		return nil, false
	}
	var recs []Record
	collect := func(rrs []dns.RR) {
		for _, rr := range rrs {
			if rec, ok := toRecord(rr); ok {
				recs = append(recs, rec)
			}
		}
	}
	collect(msg.Answer)
	collect(msg.Ns)
	collect(msg.Extra)
	return recs, len(recs) > 0
}

func toRecord(rr dns.RR) (Record, bool) {
	h := rr.Header()
	// miekg Unpack 会将域名中的特殊字符（空格、()、[]、@、;、"）转义为 "\(" 形式，
	// 此处统一反转为原始字节，保证 banner 输出与深挖回查（pack 会重新转义）的一致性。
	r := Record{Name: UnescapeDomain(h.Name), TTL: h.Ttl}
	switch v := rr.(type) {
	case *dns.PTR:
		r.Type = "PTR"
		r.Target = UnescapeDomain(v.Ptr)
	case *dns.SRV:
		r.Type = "SRV"
		r.Target = UnescapeDomain(v.Target)
		r.Port = v.Port
	case *dns.TXT:
		r.Type = "TXT"
		r.TXT = ParseTXT(v.Txt)
	case *dns.A:
		r.Type = "A"
		r.IP = v.A.String()
	case *dns.AAAA:
		r.Type = "AAAA"
		r.IP = v.AAAA.String()
	default:
		return Record{}, false
	}
	return r, true
}

// UnescapeDomain 反转义域名中的转义序列：
//
//	\X   → 字面字符 X（miekg 对特殊字符的单字符转义）
//	\DDD → 十进制字节值（RFC 1035 主区域文件转义）
//
// 反转义后的名称用于展示与逻辑判断；重新 Pack 时 miekg 会按需再转义。
func UnescapeDomain(s string) string {
	if !strings.ContainsRune(s, '\\') {
		return s
	}
	var sb strings.Builder
	sb.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			sb.WriteByte(s[i])
			continue
		}
		i++
		if i >= len(s) {
			break
		}
		// \DDD 十进制转义
		if i+2 < len(s) && isDigit(s[i]) && isDigit(s[i+1]) && isDigit(s[i+2]) {
			v := int(s[i]-'0')*100 + int(s[i+1]-'0')*10 + int(s[i+2]-'0')
			if v < 256 {
				sb.WriteByte(byte(v))
				i += 2
				continue
			}
		}
		sb.WriteByte(s[i])
	}
	return sb.String()
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }

// ParseTXT 将 TXT 字符串列表解析为键值对。
// 无 "=" 的项以整串为 key、value 为空；同 key 保留首个；超长值截断。
func ParseTXT(items []string) []KV {
	var kvs []KV
	seen := map[string]bool{}
	for _, it := range items {
		k, val, _ := strings.Cut(it, "=")
		if k == "" {
			k = it
		}
		if seen[k] {
			continue
		}
		seen[k] = true
		if len(val) > 512 {
			val = val[:512]
		}
		kvs = append(kvs, KV{Key: k, Value: val})
	}
	return kvs
}

// DedupeRecords 按 (Name, Type, 内容) 去重，保持首次出现顺序。
// 同一 (ip,port) 的多轮响应可能重复携带相同记录。
func DedupeRecords(recs []Record) []Record {
	seen := make(map[string]struct{}, len(recs))
	out := make([]Record, 0, len(recs))
	for _, r := range recs {
		key := r.dedupeKey()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, r)
	}
	return out
}

func (r Record) dedupeKey() string {
	switch r.Type {
	case "PTR":
		return "PTR|" + r.Name + "|" + r.Target
	case "SRV":
		return "SRV|" + r.Name + "|" + r.Target + "|" + strconv.Itoa(int(r.Port))
	case "TXT":
		var sb strings.Builder
		sb.WriteString("TXT|")
		sb.WriteString(r.Name)
		sb.WriteByte('|')
		for _, kv := range r.TXT {
			sb.WriteString(kv.Key)
			sb.WriteByte('=')
			sb.WriteString(kv.Value)
			sb.WriteByte(';')
		}
		return sb.String()
	default:
		return r.Type + "|" + r.Name + "|" + r.IP
	}
}
