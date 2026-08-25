// Package output 渲染扫描结果：JSON（默认）、JSONL 与任务示例同构的 text 格式。
//
// text 格式（验收对照格式，与 main.go 示例逐行同构）：
//
//	ip=192.168.1.100 port=5353 host=slw-nas.local
//	services:
//	  9/tcp workstation:
//	    Name=slw-nas [24:5e:be:69:a3:13]
//	    IPv4=192.168.1.100
//	    IPv6=fe80::265e:beff:fe69:a313
//	    Hostname=slw-nas.local
//	    TTL=10
//	answers:
//	  PTR:
//	    _workstation._tcp.local
package output

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"huashun-demo/internal/mdns"
	"huashun-demo/internal/probe"
)

// Asset 是输出层的单个资产（host 为聚合出的主主机名，无则回退为 IP）。
type Asset struct {
	IP     string       `json:"ip"`
	Port   int          `json:"port"`
	Host   string       `json:"host"`
	Banner *mdns.Banner `json:"banner"`
}

// FromResults 将探测结果转换为输出资产（按 IP、端口排序）。
func FromResults(results []probe.Result) []Asset {
	assets := make([]Asset, 0, len(results))
	for _, r := range results {
		host := r.Banner.PrimaryHost()
		if host == "" {
			host = r.IP
		}
		assets = append(assets, Asset{IP: r.IP, Port: r.Port, Host: host, Banner: r.Banner})
	}
	sort.Slice(assets, func(i, j int) bool {
		if assets[i].IP != assets[j].IP {
			return assets[i].IP < assets[j].IP
		}
		return assets[i].Port < assets[j].Port
	})
	return assets
}

// RenderJSON 整体输出 {"assets": [...]}（缩进两空格）。
func RenderJSON(w io.Writer, assets []Asset) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(struct {
		Assets []Asset `json:"assets"`
	}{Assets: assets})
}

// RenderJSONL 按 JSON Lines 逐行输出（便于流式进管道/数据库）。
func RenderJSONL(w io.Writer, assets []Asset) error {
	for _, a := range assets {
		b, err := json.Marshal(a)
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintln(w, string(b)); err != nil {
			return err
		}
	}
	return nil
}

// RenderText 输出与任务示例同构的缩进文本。多资产之间以空行分隔。
func RenderText(w io.Writer, assets []Asset) error {
	for i, a := range assets {
		if i > 0 {
			if _, err := fmt.Fprintln(w); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintf(w, "ip=%s port=%d host=%s\n", a.IP, a.Port, a.Host); err != nil {
			return err
		}
		if err := renderBanner(w, a.Banner); err != nil {
			return err
		}
	}
	return nil
}

func renderBanner(w io.Writer, b *mdns.Banner) error {
	if b == nil || len(b.Services) == 0 {
		return nil
	}
	if _, err := fmt.Fprintln(w, "services:"); err != nil {
		return err
	}
	keys := make([]string, 0, len(b.Services))
	for k := range b.Services {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		e := b.Services[k]
		if _, err := fmt.Fprintf(w, "  %s:\n", k); err != nil {
			return err
		}
		lines := make([]string, 0, 5+len(e.TXT))
		if e.Name != "" {
			lines = append(lines, "Name="+e.Name)
		}
		if len(e.IPv4) > 0 {
			lines = append(lines, "IPv4="+strings.Join(e.IPv4, ","))
		}
		if len(e.IPv6) > 0 {
			lines = append(lines, "IPv6="+strings.Join(e.IPv6, ","))
		}
		if e.Hostname != "" {
			lines = append(lines, "Hostname="+e.Hostname)
		}
		if e.TTL > 0 {
			lines = append(lines, fmt.Sprintf("TTL=%d", e.TTL))
		}
		if len(e.TXT) > 0 {
			// TXT 深度键值：多键时单行逗号连接（与任务示例同构），单键时直接 "k=v"
			parts := make([]string, 0, len(e.TXT))
			for _, kv := range e.TXT {
				parts = append(parts, kv.Key+"="+kv.Value)
			}
			lines = append(lines, strings.Join(parts, ","))
		}
		for _, ln := range lines {
			if _, err := fmt.Fprintf(w, "    %s\n", ln); err != nil {
				return err
			}
		}
	}
	if len(b.PTRAnswers) > 0 {
		if _, err := fmt.Fprintln(w, "answers:"); err != nil {
			return err
		}
		if _, err := fmt.Fprintln(w, "  PTR:"); err != nil {
			return err
		}
		for _, p := range b.PTRAnswers {
			if _, err := fmt.Fprintf(w, "    %s\n", p); err != nil {
				return err
			}
		}
	}
	return nil
}
