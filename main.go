package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	yaml "github.com/goccy/go-yaml"
)

//////////////////// STRUCTS ////////////////////

type DNSFallbackFilter struct {
	GeoIP  bool     `yaml:"geoip"`
	IPCIDR []string `yaml:"ipcidr"`
}

type DNSConfig struct {
	Enabled        bool              `yaml:"enabled"`
	Nameserver     []string          `yaml:"nameserver"`
	Fallback       []string          `yaml:"fallback"`
	FallbackFilter DNSFallbackFilter `yaml:"fallback-filter"`
}

type Proxy struct {
	Name   string `yaml:"name"`
	Type   string `yaml:"type"`
	Server string `yaml:"server"`
	Port   int    `yaml:"port"`
	UUID   string `yaml:"uuid"`

	AlterID int    `yaml:"alterId"`
	Cipher  string `yaml:"cipher"`

	TLS            bool   `yaml:"tls,omitempty"`
	SkipCertVerify bool   `yaml:"skip-cert-verify,omitempty"`
	ServerName     string `yaml:"servername,omitempty"`

	Network string `yaml:"network,omitempty"`
	WSOpts  any    `yaml:"ws-opts,omitempty"`
}

type ProxyGroup struct {
	Name      string   `yaml:"name"`
	Type      string   `yaml:"type"`
	URL       string   `yaml:"url"`
	Interval  int      `yaml:"interval"`
	Tolerance int      `yaml:"tolerance"`
	Proxies   []string `yaml:"proxies"`
}

type ClashConfig struct {
	MixedPort          int          `yaml:"mixed-port"`
	AllowLan           bool         `yaml:"allow-lan"`
	LogLevel           string       `yaml:"log-level"`
	ExternalController string       `yaml:"external-controller"`
	IPv6               bool         `yaml:"ipv6"`
	DNS                DNSConfig    `yaml:"dns"`
	Proxies            []Proxy      `yaml:"proxies"`
	ProxyGroups        []ProxyGroup `yaml:"proxy-groups"`
	Rules              []string     `yaml:"rules"`
}

//////////////////// HELPERS ////////////////////

var emojiRegex = regexp.MustCompile(`[\x{1F300}-\x{1FAFF}]`)
var usageRegex = regexp.MustCompile(`([\d.]+)GB`)

func cleanName(name string) string {
	name = emojiRegex.ReplaceAllString(name, "")
	return strings.TrimSpace(name)
}

func gbToBytes(gb float64) int64 {
	return int64(gb * 1024 * 1024 * 1024)
}

func parseExpire(dateStr string) int64 {
	t, err := time.Parse("2006/01/02", dateStr)
	if err != nil {
		return 0
	}
	return t.Unix()
}

func extractUsedGB(name string) float64 {
	m := usageRegex.FindStringSubmatch(name)
	if len(m) < 2 {
		return 0
	}
	v, _ := strconv.ParseFloat(m[1], 64)
	return v
}

//////////////////// NETWORK ////////////////////

func fetchSubscription(subURL string) (string, error) {
	req, _ := http.NewRequest("GET", subURL, nil)
	req.Header.Set("User-Agent", "curl/7.88.1")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	return string(body), nil
}

func decodeBase64(input string) (string, error) {
	input = strings.TrimSpace(input)

	if data, err := base64.StdEncoding.DecodeString(input); err == nil {
		return string(data), nil
	}
	if data, err := base64.RawStdEncoding.DecodeString(input); err == nil {
		return string(data), nil
	}
	return "", fmt.Errorf("invalid base64")
}

//////////////////// VLESS ////////////////////

func parseVLESS(link string) *Proxy {
	u, err := url.Parse(link)
	if err != nil {
		return nil
	}

	q := u.Query()
	port, _ := strconv.Atoi(u.Port())

	name := cleanName(u.Fragment)
	if name == "" {
		name = u.Hostname()
	}

	proxy := &Proxy{
		Name:    name,
		Type:    "vless",
		Server:  u.Hostname(),
		Port:    port,
		UUID:    u.User.Username(),
		AlterID: 0,
		Cipher:  "auto",
	}

	if q.Get("security") == "tls" {
		proxy.TLS = true
		proxy.SkipCertVerify = true
		sni := q.Get("sni")
		if sni == "" {
			sni = u.Hostname()
		}
		proxy.ServerName = sni
	}

	if q.Get("type") == "ws" {
		proxy.Network = "ws"
		proxy.WSOpts = map[string]any{
			"path": q.Get("path"),
			"headers": map[string]string{
				"host": q.Get("host"),
			},
		}
	}

	return proxy
}

//////////////////// BUILD CONFIG ////////////////////

func buildConfig(decoded string) ([]byte, []Proxy, error) {
	lines := strings.Split(decoded, "\n")

	var proxies []Proxy
	var proxyNames []string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "vless://") {
			p := parseVLESS(line)
			if p != nil {
				proxies = append(proxies, *p)
				proxyNames = append(proxyNames, p.Name)
			}
		}
	}

	config := ClashConfig{
		MixedPort:          7890,
		AllowLan:           false,
		LogLevel:           "info",
		ExternalController: "127.0.0.1:9090",
		IPv6:               false,
		DNS: DNSConfig{
			Enabled:    true,
			Nameserver: []string{"1.1.1.1", "8.8.8.8"},
			Fallback:   []string{"1.0.0.1", "8.8.4.4"},
			FallbackFilter: DNSFallbackFilter{
				GeoIP: true,
				IPCIDR: []string{
					"10.0.0.0/8","100.64.0.0/10","169.254.0.0/16",
					"172.16.0.0/12","192.0.0.0/24","198.18.0.0/15",
					"240.0.0.0/4","64:ff9b:1::/48","fc00::/7","fe80::/64",
				},
			},
		},
		Proxies: proxies,
		ProxyGroups: []ProxyGroup{
			{
				Name:      "maingroup",
				Type:      "url-test",
				URL:       "https://speed.cloudflare.com/__down?bytes=100",
				Interval:  30,
				Tolerance: 300,
				Proxies:   proxyNames,
			},
		},
		Rules: []string{
			"GEOIP,private,DIRECT,no-resolve",
			"GEOIP,IR,DIRECT",
			"MATCH,maingroup",
		},
	}

	out, err := yaml.MarshalWithOptions(config, yaml.Indent(2), yaml.IndentSequence(true))
	return out, proxies, err
}

//////////////////// HANDLER ////////////////////

func handler(w http.ResponseWriter, r *http.Request) {
	base := os.Getenv("SUB_BASE")
	path := strings.TrimPrefix(r.URL.Path, "/")
	subURL := strings.TrimRight(base, "/") + "/" + path

	raw, _ := fetchSubscription(subURL)
	decoded, _ := decodeBase64(raw)

	out, proxies, _ := buildConfig(decoded)

	// ---- read query ----
	q := r.URL.Query()
	totalGB, _ := strconv.ParseFloat(q.Get("total"), 64)
	expireUnix := parseExpire(q.Get("expire"))

	totalTraffic := gbToBytes(totalGB)

	// ⭐ ONLY FIRST PROXY
	var usedDownload int64
	if len(proxies) > 0 {
		usedGB := extractUsedGB(proxies[0].Name)
		usedDownload = gbToBytes(usedGB)
	}

	userinfo := fmt.Sprintf(
		"upload=%d; download=%d; total=%d; expire=%d",
		0, usedDownload, totalTraffic, expireUnix,
	)

	w.Header().Set("Content-Type", "text/yaml")
	w.Header().Set("Subscription-Userinfo", userinfo)
	w.Header().Set("Profile-Update-Interval", "24")
	w.Header().Set("Content-Disposition", "attachment; filename=clash.yaml")

	w.Write(out)
}

//////////////////// MAIN ////////////////////

func main() {
	servMode := flag.Bool("serv", false, "run as server")
	flag.Parse()

	if *servMode {
		listen := os.Getenv("LISTEN")
		if listen == "" {
			listen = ":8080"
		}
		http.HandleFunc("/", handler)
		fmt.Println("Server running on", listen)
		http.ListenAndServe(listen, nil)
		return
	}

	fmt.Println("Use --serv mode")
}
