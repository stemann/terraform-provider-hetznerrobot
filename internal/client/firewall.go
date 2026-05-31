package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Firewall defines the body format for /firewall requests.
type Firewall struct {
	IP                       string        `json:"ip"`
	WhitelistHetznerServices bool          `json:"whitelist_hos"`
	FilterIPv6               bool          `json:"filter_ipv6"`
	Status                   string        `json:"status"`
	Rules                    FirewallRules `json:"rules"`
}

// FirewallRules defines the firewall rules for Firewall.
type FirewallRules struct {
	Input []FirewallRule `json:"input"`
}

// FirewallRule defines a firewall rule for FirewallRules.
type FirewallRule struct {
	IPVersion string `json:"ip_version,omitempty"`
	Name      string `json:"name,omitempty"`
	SrcIP     string `json:"src_ip,omitempty"`
	SrcPort   string `json:"src_port,omitempty"`
	DstIP     string `json:"dst_ip,omitempty"`
	DstPort   string `json:"dst_port,omitempty"`
	Protocol  string `json:"protocol,omitempty"`
	TCPFlags  string `json:"tcp_flags,omitempty"`
	Action    string `json:"action"`
}

// FirewallResponse defines the response from /firewall.
type FirewallResponse struct {
	Firewall Firewall `json:"firewall"`
}

// GetFirewall returns info about from a server ip.
func (c *HetznerRobotClient) GetFirewall(ctx context.Context, ip string) (*Firewall, error) {
	path := "/firewall/" + ip

	resp, err := c.DoRequest(ctx, "GET", path, nil, "")
	if err != nil {
		return nil, fmt.Errorf("failed to get firewall: %w", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		data, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("unable to read response body: %w", err)
		}

		return nil, fmt.Errorf("unexpected response status: %d, body: %s", resp.StatusCode, data)
	}

	var fwResp FirewallResponse

	err = json.NewDecoder(resp.Body).Decode(&fwResp)
	if err != nil {
		return nil, fmt.Errorf("failed to parse firewall response: %w", err)
	}

	return &fwResp.Firewall, nil
}

// SetFirewall sets firewall rules for a server ip.
func (c *HetznerRobotClient) SetFirewall(
	ctx context.Context,
	firewall Firewall,
) error {
	path := "/firewall/" + firewall.IP

	data := url.Values{}
	data.Set("whitelist_hos", strconv.FormatBool(firewall.WhitelistHetznerServices))
	data.Set("filter_ipv6", strconv.FormatBool(firewall.FilterIPv6))
	data.Set("status", firewall.Status)

	for index, rule := range firewall.Rules.Input {
		// Default to ipv4 when the caller doesn't specify.
		ipVersion := rule.IPVersion
		if ipVersion == "" {
			ipVersion = "ipv4"
		}

		data.Set(fmt.Sprintf("rules[input][%d][ip_version]", index), ipVersion)

		fields := map[string]string{
			"name":      rule.Name,
			"src_ip":    rule.SrcIP,
			"src_port":  rule.SrcPort,
			"dst_ip":    rule.DstIP,
			"dst_port":  rule.DstPort,
			"protocol":  rule.Protocol,
			"tcp_flags": rule.TCPFlags,
		}

		for key, value := range fields {
			if value != "" {
				data.Set(fmt.Sprintf("rules[input][%d][%s]", index, key), value)
			}
		}

		data.Set(fmt.Sprintf("rules[input][%d][action]", index), rule.Action)
	}

	resp, err := c.DoRequest(
		ctx,
		"POST",
		path,
		strings.NewReader(data.Encode()),
		"application/x-www-form-urlencoded",
	)
	if err != nil {
		return fmt.Errorf("failed to set firewall: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		data, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("unable to read response body: %w", err)
		}

		return fmt.Errorf("unexpected response status: %d, body: %s", resp.StatusCode, data)
	}

	return c.waitForFirewallActive(ctx, firewall.IP)
}

func (c *HetznerRobotClient) waitForFirewallActive(
	ctx context.Context,
	ip string,
) error {
	for range waitMaxRetries {
		firewall, err := c.GetFirewall(ctx, ip)
		if err != nil {
			return fmt.Errorf("error checking firewall status: %w", err)
		}

		if firewall.Status == "active" {
			return nil
		}

		time.Sleep(waitDuration)
	}

	return fmt.Errorf("timeout waiting for firewall to become active on ip: %s", ip)
}
