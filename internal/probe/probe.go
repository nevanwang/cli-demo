// Package probe 实现 UDP 层的 mDNS 探测：单播收发、并发调度、限速、组播扫描。
//
// 扫描管线（单播）：
//
//	        ┌─────────────────────────────────────────────┐
//	targets │ worker 池（Concurrency 个 goroutine）         │
//	──────▶ │  识别轮: ProbeQueries ─▶ exchange ─▶ 无记录?  │──▶ 放弃
//	        │            │ 有记录（判定为 mDNS 资产）         │
//	        │            ▼                                │
//	        │  深挖轮: FollowUpQueries ─▶ exchange ─▶ 合并   │
//	        │            ▼                                │
//	        │  Aggregate ─▶ Result                        │
//	        └─────────────────────────────────────────────┘
package probe

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/miekg/dns"

	"huashun-demo/internal/mdns"
	"huashun-demo/internal/target"
)

// Options 探测配置。
type Options struct {
	// Timeout 单轮收包窗口时长。
	Timeout time.Duration
	// Retries 识别轮无响应时的重试次数（0 = 只发一次）。
	Retries int
	// Concurrency 识别轮并发 worker 数。
	Concurrency int
	// RateLimit 全局发包速率上限（包/秒，0 = 不限）。
	RateLimit int
	// Logger 调试日志（可为 nil）。
	Logger *slog.Logger
}

func (o *Options) setDefaults() {
	if o.Timeout <= 0 {
		o.Timeout = 1500 * time.Millisecond
	}
	if o.Retries < 0 {
		o.Retries = 0
	}
	if o.Concurrency <= 0 {
		o.Concurrency = 512
	}
	if o.RateLimit < 0 {
		o.RateLimit = 0
	}
}

func (o *Options) logger() *slog.Logger {
	if o.Logger != nil {
		return o.Logger
	}
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// Result 是单个资产 (ip, port) 的扫描结果。
type Result struct {
	IP     string
	Port   int
	Banner *mdns.Banner
}

// ScanUnicast 对全部目标执行 识别轮 → 深挖轮 → 聚合 管线（单播探测）。
// ctx 取消时尽快返回已发现的结果。
func ScanUnicast(ctx context.Context, targets []target.Target, opts Options) []Result {
	opts.setDefaults()
	log := opts.logger()
	limiter := newRateLimiter(ctx, opts.RateLimit)
	probeQs := mdns.ProbeQueries()

	var (
		mu      sync.Mutex
		wg      sync.WaitGroup
		results []Result
	)
	sem := make(chan struct{}, opts.Concurrency)

	for i := range targets {
		t := targets[i]
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			if ctx.Err() != nil {
				return
			}

			recs, err := exchange(ctx, t.Addr(), probeQs, opts.Timeout, opts.Retries, limiter)
			if err != nil || len(recs) == 0 {
				return // 无合法 DNS 响应：不是 mDNS 资产
			}
			log.Debug("识别轮命中", "addr", t.Addr(), "records", len(recs))

			// 深挖轮：仅对存活资产补查缺失记录（无重试）
			if follow := mdns.FollowUpQueries(recs, mdns.MaxFollowUpQueries); len(follow) > 0 {
				msgs := make([]*dns.Msg, 0, len(follow))
				for _, q := range follow {
					msgs = append(msgs, q.Build())
				}
				recs2, err := exchange(ctx, t.Addr(), msgs, opts.Timeout, 0, limiter)
				if err == nil {
					recs = append(recs, recs2...)
				}
			}

			banner := mdns.Aggregate(recs)
			mu.Lock()
			results = append(results, Result{IP: t.IP.String(), Port: t.Port, Banner: banner})
			mu.Unlock()
		}()
	}
	wg.Wait()

	sort.Slice(results, func(i, j int) bool {
		if results[i].IP != results[j].IP {
			return results[i].IP < results[j].IP
		}
		return results[i].Port < results[j].Port
	})
	return results
}

// exchange 在单个 connected UDP socket 上发送全部查询并收集响应记录，
// 直到收包窗口超时。无响应且 retries > 0 时整组重发。
// connected socket 天然过滤非目标来源的包。
func exchange(ctx context.Context, addr string, queries []*dns.Msg, timeout time.Duration, retries int, rl *rateLimiter) ([]mdns.Record, error) {
	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	var all []mdns.Record
	buf := make([]byte, mdns.MaxResponseSize)

	for attempt := 0; attempt <= retries; attempt++ {
		for _, q := range queries {
			if ctx.Err() != nil {
				return all, ctx.Err()
			}
			if err := rl.wait(ctx); err != nil {
				return all, err
			}
			wire, err := q.Pack()
			if err != nil {
				continue
			}
			_ = conn.SetWriteDeadline(time.Now().Add(timeout))
			if _, err := conn.Write(wire); err != nil {
				break // 发送失败（网络不可达等）：结束本轮
			}
		}
		deadline := time.Now().Add(timeout)
		for {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				break
			}
			_ = conn.SetReadDeadline(time.Now().Add(remaining))
			n, err := conn.Read(buf)
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					break
				}
				return all, nil // 连接级错误（如 ICMP 端口不可达）：返回已收集
			}
			if recs, ok := mdns.ParseResponse(buf[:n]); ok {
				all = append(all, recs...)
			}
		}
		if len(all) > 0 {
			break // 已有响应，无需重试
		}
	}
	return all, nil
}

// rateLimiter 是简单的令牌桶限速器（容量 = rate，每 1/rate 秒补充一枚）。
type rateLimiter struct {
	tokens chan struct{}
}

func newRateLimiter(ctx context.Context, rate int) *rateLimiter {
	if rate <= 0 {
		return nil
	}
	l := &rateLimiter{tokens: make(chan struct{}, rate)}
	interval := time.Second / time.Duration(rate)
	if interval <= 0 {
		interval = time.Microsecond
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				select {
				case l.tokens <- struct{}{}:
				default:
				}
			}
		}
	}()
	return l
}

func (l *rateLimiter) wait(ctx context.Context) error {
	if l == nil {
		return nil
	}
	select {
	case <-l.tokens:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// ScanMulticast 通过 224.0.0.251:5353 组播探测：
// 查询带 QU bit，响应者会单播回包；聚合源 IP 位于给定网段、
// 源端口位于给定端口集合的响应者，再对每个发现者做单播深挖。
func ScanMulticast(ctx context.Context, cidrs []*net.IPNet, ports []int, opts Options) []Result {
	opts.setDefaults()
	log := opts.logger()

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		log.Warn("组播监听失败", "err", err)
		return nil
	}
	defer conn.Close()

	maddr := &net.UDPAddr{IP: net.ParseIP(mdns.MulticastGroup4), Port: mdns.MDNSPort}
	total := opts.Timeout * time.Duration(opts.Retries+1)
	runCtx, cancel := context.WithTimeout(ctx, total)
	defer cancel()

	type srcKey struct {
		ip   string
		port int
	}
	collected := map[srcKey][]mdns.Record{}

	// 发包循环：按 retries+1 轮重发探针组
	sendDone := make(chan struct{})
	go func() {
		defer close(sendDone)
		qs := mdns.ProbeQueries()
		for round := 0; round <= opts.Retries; round++ {
			for _, q := range qs {
				if runCtx.Err() != nil {
					return
				}
				wire, err := q.Pack()
				if err != nil {
					continue
				}
				_ = conn.SetWriteDeadline(time.Now().Add(opts.Timeout))
				if _, err := conn.WriteToUDP(wire, maddr); err != nil {
					log.Debug("组播发送失败", "err", err)
					return
				}
				time.Sleep(20 * time.Millisecond) // 平滑突发
			}
			select {
			case <-time.After(opts.Timeout):
			case <-runCtx.Done():
				return
			}
		}
	}()

	buf := make([]byte, mdns.MaxResponseSize)
	deadline := time.Now().Add(total)
	for {
		_ = conn.SetReadDeadline(deadline)
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			break // 总窗口结束
		}
		if runCtx.Err() != nil {
			break
		}
		recs, ok := mdns.ParseResponse(buf[:n])
		if !ok {
			continue
		}
		if !ipInAny(src.IP, cidrs) {
			continue
		}
		if !intIn(src.Port, ports) {
			continue
		}
		key := srcKey{ip: src.IP.String(), port: src.Port}
		collected[key] = append(collected[key], recs...)
	}
	<-sendDone

	var results []Result
	for key, recs := range collected {
		all := recs
		if follow := mdns.FollowUpQueries(recs, mdns.MaxFollowUpQueries); len(follow) > 0 {
			msgs := make([]*dns.Msg, 0, len(follow))
			for _, q := range follow {
				msgs = append(msgs, q.Build())
			}
			if recs2, err := exchange(ctx, fmt.Sprintf("%s:%d", key.ip, key.port), msgs, opts.Timeout, 0, nil); err == nil {
				all = append(all, recs2...)
			}
		}
		results = append(results, Result{IP: key.ip, Port: key.port, Banner: mdns.Aggregate(all)})
	}

	sort.Slice(results, func(i, j int) bool {
		if results[i].IP != results[j].IP {
			return results[i].IP < results[j].IP
		}
		return results[i].Port < results[j].Port
	})
	return results
}

func ipInAny(ip net.IP, cidrs []*net.IPNet) bool {
	for _, c := range cidrs {
		if c.Contains(ip) {
			return true
		}
	}
	return false
}

func intIn(v int, list []int) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
