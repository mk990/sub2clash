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

	yaml "github.com/goccy/go-yaml"
)

type ClashConfig struct {
	MixedPort          int                      `yaml:"mixed-port"`
	AllowLan           bool                     `yaml:"allow-lan"`
	LogLevel           string                   `yaml:"log-level"`
	ExternalController string                   `yaml:"external-controller"`
	IPv6               bool                     `yaml:"ipv6"`
	DNS                map[string]interface{}   `yaml:"dns"`
	Proxies            []map[string]interface{} `yaml:"proxies"`
	ProxyGroups        []map[string]interface{} `yaml:"proxy-groups"`
	Rules              []string                 `yaml:"rules"`
}

var emojiRegex = regexp.MustCompile(`[\x{1F300}-\x{1FAFF}]`)

func cleanName(name string) string {
	name = emojiRegex.ReplaceAllString(name, "")
	return strings.TrimSpace(name)
}

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

func parseVLESS(link string) map[string]interface{} {
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

	proxy := map[string]interface{}{
		"name":    name,
		"type":    "vless",
		"server":  u.Hostname(),
		"port":    port,
		"uuid":    u.User.Username(),
		"alterId": 0,
		"cipher":  "auto",
	}

	if q.Get("security") == "tls" {
		proxy["tls"] = true
		proxy["skip-cert-verify"] = true

		sni := q.Get("sni")
		if sni == "" {
			sni = u.Hostname()
		}
		proxy["servername"] = sni
	}

	if q.Get("type") == "ws" {
		proxy["network"] = "ws"
		proxy["ws-opts"] = map[string]interface{}{
			"path": q.Get("path"),
			"headers": map[string]string{
				"host": q.Get("host"),
			},
		}
	}

	return proxy
}

func buildConfig(decoded string) ([]byte, error) {
	lines := strings.Split(decoded, "\n")

	var proxies []map[string]interface{}
	var proxyNames []string

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "vless://") {
			p := parseVLESS(line)
			if p != nil {
				proxies = append(proxies, p)
				proxyNames = append(proxyNames, p["name"].(string))
			}
		}
	}

	config := ClashConfig{
		MixedPort:          7890,
		AllowLan:           true,
		LogLevel:           "info",
		ExternalController: "0.0.0.0:9090",
		IPv6:               false,
		DNS: map[string]interface{}{
			"enabled": true,
			"nameserver": []string{
				"1.1.1.1",
				"4.2.2.4",
			},
		},
		Proxies: proxies,
		ProxyGroups: []map[string]interface{}{
			{
				"name":      "maingroup",
				"type":      "url-test",
				"url":       "https://speed.cloudflare.com/__down?bytes=100",
				"interval":  30,
				"tolerance": 300,
				"proxies":   proxyNames,
			},
		},
		Rules: []string{
			"MATCH,maingroup",
		},
	}

	return yaml.MarshalWithOptions(config, yaml.Indent(2))
}

func handler(w http.ResponseWriter, r *http.Request) {
	base := os.Getenv("SUB_BASE")
	if base == "" {
		http.Error(w, "SUB_BASE not set", 500)
		return
	}

	// FULL PATH PASSTHROUGH
	path := strings.TrimPrefix(r.URL.Path, "/")

	subURL := strings.TrimRight(base, "/") + "/" + path

	raw, err := fetchSubscription(subURL)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	decoded, err := decodeBase64(raw)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	out, err := buildConfig(decoded)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	w.Header().Set("Content-Type", "text/yaml")
	w.Write(out)
}

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
