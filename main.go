// mdns-scan：基于 IP 网段与端口范围的 mDNS 协议资产测绘 CLI。
//
// 数据流：
//
//	CIDR/端口参数 ──▶ target 展开为 (ip,port) 列表
//	      │
//	      ▼
//	probe 单播识别轮（QU bit 探针：枚举 + 常见服务字典）
//	      │ 命中（收到合法 DNS 响应）
//	      ▼
//	probe 深挖轮（按响应内容补查 SRV/TXT/A/AAAA）
//	      │
//	      ▼
//	mdns.Aggregate ──▶ 深度 banner ──▶ output（JSON / text）
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"huashun-demo/internal/output"
	"huashun-demo/internal/probe"
	"huashun-demo/internal/target"
)

const (
	// hardTargetLimit 目标数硬上限（(ip,port) 组合数）。
	hardTargetLimit = 1 << 20
	// confirmThreshold 超过此目标数需要 --yes 显式确认。
	confirmThreshold = 65536
)

const usageText = `mdns-scan — 基于 IP 网段与端口范围的 mDNS 资产测绘工具

用法:
  mdns-scan [选项] <CIDR|IP> [CIDR|IP ...]

示例:
  mdns-scan 192.168.1.0/24                          # 扫描 /24 网段的 5353 端口
  mdns-scan -p 5350-5360 -f text 10.0.0.5           # 端口范围 + 文本输出
  mdns-scan --multicast 192.168.1.0/24              # 附加组播探测本广播域
  mdns-scan -p 5353,5354 172.16.0.0/16 10.0.0.0/24  # 多网段多端口

探测方式:
  默认单播探测（查询带 QU bit），支持任意网段（含公网）；
  --multicast 附加 224.0.0.251:5353 组播探测，覆盖仅应答组播查询的设备。

选项:
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("mdns-scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		portSpec  = fs.String("p", "5353", `端口范围: "5353"、"5350-5360"、逗号分隔组合`)
		format    = fs.String("f", "json", "输出格式: json | text")
		jsonl     = fs.Bool("jsonl", false, "按 JSON Lines 流式输出（覆盖 -f）")
		timeout   = fs.Duration("timeout", 1500*time.Millisecond, "单目标每轮收包超时")
		retry     = fs.Int("retry", 1, "识别轮无响应时的重试次数")
		conc      = fs.Int("c", 512, "并发探测数")
		rate      = fs.Int("rate", 2000, "全局发包速率上限（包/秒，0 不限）")
		multicast = fs.Bool("multicast", false, "附加组播探测（224.0.0.251:5353）")
		verbose   = fs.Bool("v", false, "输出调试日志到 stderr")
		assumeYes = fs.Bool("yes", false, "跳过超大目标数确认")
	)
	fs.Usage = func() {
		fmt.Fprint(stderr, usageText)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() == 0 {
		fs.Usage()
		return 2
	}
	if *format != "json" && *format != "text" {
		fmt.Fprintf(stderr, "无效的输出格式 %q（支持 json | text）\n", *format)
		return 2
	}

	logLevel := slog.LevelWarn
	if *verbose {
		logLevel = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: logLevel}))

	ports, err := target.ParsePorts(*portSpec)
	if err != nil {
		fmt.Fprintf(stderr, "错误: %v\n", err)
		return 2
	}

	var ipnets []*net.IPNet
	for _, a := range fs.Args() {
		ipnet, err := target.ParseCIDR(a)
		if err != nil {
			fmt.Fprintf(stderr, "错误: %v\n", err)
			return 2
		}
		ipnets = append(ipnets, ipnet)
	}

	// 巨型网段保护：先按数量校验再展开，防内存爆炸
	var total int64
	for _, ipnet := range ipnets {
		cnt := target.Count(ipnet) * int64(len(ports))
		if cnt < 0 || total+cnt < 0 { // 溢出
			total = int64(1) << 62
			break
		}
		total += cnt
	}
	if total > hardTargetLimit {
		fmt.Fprintf(stderr, "错误: 目标数约 %d 超过硬上限 %d，请缩小网段或端口范围\n", total, hardTargetLimit)
		return 1
	}
	if total > confirmThreshold && !*assumeYes {
		fmt.Fprintf(stderr, "错误: 目标数约 %d 超过 %d，确认请加 --yes\n", total, confirmThreshold)
		return 1
	}

	var targets []target.Target
	for _, ipnet := range ipnets {
		ts, err := target.BuildTargets(ipnet, ports)
		if err != nil {
			fmt.Fprintf(stderr, "错误: 展开网段 %v 失败: %v\n", ipnet, err)
			return 1
		}
		targets = append(targets, ts...)
	}

	log.Info("开始扫描", "targets", len(targets), "ports", ports)
	start := time.Now()

	opts := probe.Options{
		Timeout:     *timeout,
		Retries:     *retry,
		Concurrency: *conc,
		RateLimit:   *rate,
		Logger:      log,
	}
	results := probe.ScanUnicast(ctx, targets, opts)
	if *multicast {
		results = append(results, probe.ScanMulticast(ctx, ipnets, ports, opts)...)
	}

	log.Info("扫描完成", "assets", len(results), "elapsed", time.Since(start).Round(time.Millisecond))

	assets := output.FromResults(results)

	switch {
	case *jsonl:
		err = output.RenderJSONL(stdout, assets)
	case *format == "text":
		err = output.RenderText(stdout, assets)
	default:
		err = output.RenderJSON(stdout, assets)
	}
	if err != nil {
		fmt.Fprintf(stderr, "错误: 输出失败: %v\n", err)
		return 1
	}
	return 0
}
