package mdns

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// packMsg 将 dns.Msg 打包为 wire 格式（测试 fixture 构造用）。
func packMsg(t *testing.T, m *dns.Msg) []byte {
	t.Helper()
	wire, err := m.Pack()
	if err != nil {
		t.Fatalf("Pack 失败: %v", err)
	}
	return wire
}

func TestParseResponseRecords(t *testing.T) {
	m := new(dns.Msg)
	m.Response = true
	m.Id = 0
	m.Answer = []dns.RR{
		&dns.PTR{Hdr: dns.RR_Header{Name: "_http._tcp.local.", Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 10}, Ptr: "slw-nas._http._tcp.local."},
	}
	m.Extra = []dns.RR{
		&dns.SRV{Hdr: dns.RR_Header{Name: "slw-nas._http._tcp.local.", Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: 10}, Port: 5000, Target: "slw-nas.local."},
		&dns.TXT{Hdr: dns.RR_Header{Name: "slw-nas._http._tcp.local.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 10}, Txt: []string{"path=/"}},
		&dns.A{Hdr: dns.RR_Header{Name: "slw-nas.local.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 10}, A: []byte{192, 168, 1, 100}},
		&dns.AAAA{Hdr: dns.RR_Header{Name: "slw-nas.local.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 10}, AAAA: []byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x26, 0x5e, 0xbe, 0xff, 0xfe, 0x69, 0xa3, 0x13}},
		// authority 段也放一条（验证三段全收）
	}
	m.Ns = []dns.RR{
		&dns.PTR{Hdr: dns.RR_Header{Name: "_smb._tcp.local.", Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 10}, Ptr: "slw-nas._smb._tcp.local."},
	}

	recs, ok := ParseResponse(packMsg(t, m))
	if !ok {
		t.Fatal("期望解析成功")
	}
	if len(recs) != 6 {
		t.Fatalf("期望 6 条记录，实际 %d", len(recs))
	}

	byType := map[string]Record{}
	ptrTargets := map[string]bool{}
	for _, r := range recs {
		if r.Type == "PTR" {
			ptrTargets[r.Name+"→"+r.Target] = true
		}
		byType[r.Type] = r
	}
	if !ptrTargets["_http._tcp.local.→slw-nas._http._tcp.local."] {
		t.Errorf("answer 段 PTR 缺失: %v", ptrTargets)
	}
	if !ptrTargets["_smb._tcp.local.→slw-nas._smb._tcp.local."] {
		t.Errorf("authority 段 PTR 缺失: %v", ptrTargets)
	}
	if p := byType["PTR"]; p.TTL != 10 {
		t.Errorf("PTR 记录 TTL 错误: %+v", p)
	}
	if s := byType["SRV"]; s.Port != 5000 || s.Target != "slw-nas.local." {
		t.Errorf("SRV 记录错误: %+v", s)
	}
	if x := byType["TXT"]; len(x.TXT) != 1 || x.TXT[0].Key != "path" || x.TXT[0].Value != "/" {
		t.Errorf("TXT 记录错误: %+v", x.TXT)
	}
	if a := byType["A"]; a.IP != "192.168.1.100" {
		t.Errorf("A 记录错误: %+v", a)
	}
	if aaaa := byType["AAAA"]; aaaa.IP != "fe80::265e:beff:fe69:a313" {
		t.Errorf("AAAA 记录错误: %+v", aaaa)
	}
	// authority 段的 PTR 也应被收集（2 条 PTR）
	ptrCount := 0
	for _, r := range recs {
		if r.Type == "PTR" {
			ptrCount++
		}
	}
	if ptrCount != 2 {
		t.Errorf("期望 2 条 PTR（answer+authority），实际 %d", ptrCount)
	}
}

func TestParseResponseRejects(t *testing.T) {
	// 查询包（QR=0）应被拒绝
	q := BuildPtrQuery("_http._tcp.local.")
	if _, ok := ParseResponse(packMsg(t, q)); ok {
		t.Error("查询包不应被解析为响应")
	}
	// 畸形包
	if _, ok := ParseResponse([]byte{1, 2, 3}); ok {
		t.Error("畸形包不应被解析")
	}
	if _, ok := ParseResponse(nil); ok {
		t.Error("空包不应被解析")
	}
	// 非法 wire（足够长但格式错误）
	if _, ok := ParseResponse([]byte{0, 0, 0x80, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff}); ok {
		t.Error("非法 wire 不应被解析")
	}
	// 无识别类型的响应（如只有 OPT）→ ok=false
	m := new(dns.Msg)
	m.Response = true
	m.Extra = []dns.RR{&dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}}
	if _, ok := ParseResponse(packMsg(t, m)); ok {
		t.Error("仅含 OPT 的响应应视为无记录")
	}
}

func TestParseResponseCompressed(t *testing.T) {
	// 压缩指针响应：构造后开 Compress 打包，验证解析端处理
	m := new(dns.Msg)
	m.Response = true
	m.Compress = true
	m.Answer = []dns.RR{
		&dns.PTR{Hdr: dns.RR_Header{Name: "_services._dns-sd._udp.local.", Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 10}, Ptr: "_workstation._tcp.local."},
		&dns.PTR{Hdr: dns.RR_Header{Name: "_services._dns-sd._udp.local.", Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 10}, Ptr: "_http._tcp.local."},
		&dns.SRV{Hdr: dns.RR_Header{Name: "slw-nas._http._tcp.local.", Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: 10}, Port: 5000, Target: "slw-nas.local."},
	}
	recs, ok := ParseResponse(packMsg(t, m))
	if !ok {
		t.Fatal("压缩响应解析失败")
	}
	if len(recs) != 3 {
		t.Fatalf("期望 3 条记录，实际 %d", len(recs))
	}
	if recs[2].Target != "slw-nas.local." || recs[2].Port != 5000 {
		t.Errorf("压缩响应中的 SRV 解析错误: %+v", recs[2])
	}
}

func TestUnescapeDomain(t *testing.T) {
	tests := []struct{ in, want string }{
		{in: "_workstation._tcp.local.", want: "_workstation._tcp.local."},
		{in: `slw-nas\ \(AFP\)._device-info._tcp.local.`, want: "slw-nas (AFP)._device-info._tcp.local."},
		{in: `slw-nas\ [24:5e:be:69:a3:13]._workstation._tcp.local.`, want: "slw-nas [24:5e:be:69:a3:13]._workstation._tcp.local."},
		{in: `a\046b.local.`, want: "a.b.local."}, // \046 = '.'
		{in: `trailing\\`, want: `trailing\`},     // \\ → 字面反斜杠
	}
	for _, tt := range tests {
		if got := UnescapeDomain(tt.in); got != tt.want {
			t.Errorf("UnescapeDomain(%q) = %q, 期望 %q", tt.in, got, tt.want)
		}
	}
}

func TestParseTXT(t *testing.T) {
	kvs := ParseTXT([]string{"a=1", "b=2", "novalue", "a=99", "long=" + strings.Repeat("x", 600)})
	if len(kvs) != 4 {
		t.Fatalf("期望 4 个键值对，实际 %d", len(kvs))
	}
	if kvs[0].Key != "a" || kvs[0].Value != "1" {
		t.Errorf("kvs[0] = %+v", kvs[0])
	}
	if kvs[2].Key != "novalue" || kvs[2].Value != "" {
		t.Errorf("无 = 项处理错误: %+v", kvs[2])
	}
	if kvs[3].Key != "long" || len(kvs[3].Value) != 512 {
		t.Errorf("超长值未截断: %d", len(kvs[3].Value))
	}
}

func TestDedupeRecords(t *testing.T) {
	recs := []Record{
		{Type: "PTR", Name: "_http._tcp.local.", Target: "slw-nas._http._tcp.local.", TTL: 10},
		{Type: "PTR", Name: "_http._tcp.local.", Target: "slw-nas._http._tcp.local.", TTL: 20}, // 重复（TTL 不同视为同记录）
		{Type: "PTR", Name: "_smb._tcp.local.", Target: "slw-nas._smb._tcp.local."},
	}
	out := DedupeRecords(recs)
	if len(out) != 2 {
		t.Fatalf("期望去重后 2 条，实际 %d", len(out))
	}
}

func TestBuildPtrQueryWire(t *testing.T) {
	q := BuildPtrQuery("_http._tcp.local.")
	wire := packMsg(t, q)
	var m dns.Msg
	if err := m.Unpack(wire); err != nil {
		t.Fatal(err)
	}
	if m.Id != 0 {
		t.Errorf("mDNS 查询 ID 应为 0，实际 %d", m.Id)
	}
	if m.Response {
		t.Error("查询不应设置 QR 位")
	}
	if len(m.Question) != 1 {
		t.Fatalf("期望 1 条 question，实际 %d", len(m.Question))
	}
	qn := m.Question[0]
	if qn.Name != "_http._tcp.local." || qn.Qtype != dns.TypePTR {
		t.Errorf("question 错误: %+v", qn)
	}
	if qn.Qclass != dns.ClassINET|0x8000 {
		t.Errorf("Qclass 应为 IN|QU(0x8001)，实际 %#x", qn.Qclass)
	}
}

func TestSafeQueryName(t *testing.T) {
	valid := []string{
		"_workstation._tcp.local.",
		"slw-nas [24:5e:be:69:a3:13]._workstation._tcp.local.",
		"slw-nas(AFP)._device-info._tcp.local.",
		"a",
	}
	for _, n := range valid {
		if !SafeQueryName(n) {
			t.Errorf("SafeQueryName(%q) 期望 true", n)
		}
	}
	invalid := []string{
		"",
		strings.Repeat("a", 254) + ".local.", // 超长
		strings.Repeat("a", 64) + ".local.",  // label 超 63
		strings.Repeat("a.", 130) + "local.", // label 数超限
		"bad\x00name.local.",                 // 不可打印字符
		"bad\x7fname.local.",                 // DEL
	}
	for _, n := range invalid {
		if SafeQueryName(n) {
			t.Errorf("SafeQueryName(%q) 期望 false", n)
		}
	}
}

func TestFollowUpQueries(t *testing.T) {
	records := []Record{
		// 枚举发现 _qdiscover（无实例 PTR → 需要补查）
		{Type: "PTR", Name: EnumName, Target: "_qdiscover._tcp.local."},
		// _http 已有实例 PTR + SRV + TXT（无需补查）
		{Type: "PTR", Name: "_http._tcp.local.", Target: "slw-nas._http._tcp.local."},
		{Type: "SRV", Name: "slw-nas._http._tcp.local.", Target: "slw-nas.local.", Port: 5000},
		{Type: "TXT", Name: "slw-nas._http._tcp.local.", TXT: []KV{{Key: "path", Value: "/"}}},
		// A/AAAA 已有
		{Type: "A", Name: "slw-nas.local.", IP: "192.168.1.100"},
		{Type: "AAAA", Name: "slw-nas.local.", IP: "fe80::1"},
		// 恶意名称应被过滤
		{Type: "PTR", Name: EnumName, Target: "bad\x00name.local."},
	}
	qs := FollowUpQueries(records, 64)
	if len(qs) != 1 {
		t.Fatalf("期望仅 1 条深挖查询（PTR _qdiscover），实际 %d: %+v", len(qs), qs)
	}
	if qs[0].Kind != QueryKindPTR || qs[0].Name != "_qdiscover._tcp.local." {
		t.Errorf("深挖查询错误: %+v", qs[0])
	}

	// 缺 SRV 的实例 → 实例查询
	records2 := []Record{
		{Type: "PTR", Name: "_http._tcp.local.", Target: "slw-nas._http._tcp.local."},
		{Type: "TXT", Name: "slw-nas._http._tcp.local.", TXT: []KV{{Key: "a", Value: "b"}}},
		{Type: "SRV", Name: "slw-nas._http._tcp.local.", Target: "slw-nas.local.", Port: 80},
	}
	qs2 := FollowUpQueries(records2, 64)
	// host slw-nas.local 无 A/AAAA → host 查询
	if len(qs2) != 1 || qs2[0].Kind != QueryKindHost || qs2[0].Name != "slw-nas.local." {
		t.Errorf("期望 1 条 host 查询，实际 %+v", qs2)
	}

	// 上限截断
	records3 := make([]Record, 0, 100)
	for i := 0; i < 100; i++ {
		records3 = append(records3, Record{Type: "PTR", Name: EnumName, Target: "_svc" + strings.Repeat("a", i%10) + itoa(i) + "._tcp.local."})
	}
	qs3 := FollowUpQueries(records3, 10)
	if len(qs3) != 10 {
		t.Errorf("期望截断为 10，实际 %d", len(qs3))
	}
}

func itoa(i int) string {
	return string(rune('0' + i%10))
}
