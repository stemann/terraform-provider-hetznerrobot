package client_test

import (
	"context"
	"testing"

	"github.com/yellowhat/terraform-provider-hetznerrobot/internal/client"
)

//nolint:gochecknoglobals
var testFirewall = client.Firewall{
	IP:                       "1.2.3.4",
	WhitelistHetznerServices: true,
	FilterIPv6:               false,
	Status:                   "active",
	Rules: client.FirewallRules{
		//exhaustruct:ignore
		Input: []client.FirewallRule{
			{
				Name:     "allow-ssh",
				SrcIP:    "0.0.0.0/0",
				DstPort:  "22",
				Protocol: "tcp",
				Action:   "accept",
			},
			{
				Name:     "allow-http",
				SrcIP:    "0.0.0.0/0",
				DstPort:  "80",
				Protocol: "tcp",
				Action:   "accept",
			},
		},
	},
}

//nolint:gochecknoglobals
var testFirewallIPv6 = client.Firewall{
	IP:                       "1.2.3.4",
	WhitelistHetznerServices: true,
	FilterIPv6:               true,
	Status:                   "active",
	Rules: client.FirewallRules{
		//exhaustruct:ignore
		Input: []client.FirewallRule{
			{
				IPVersion: "ipv4",
				Name:      "allow-ssh",
				SrcIP:     "0.0.0.0/0",
				DstPort:   "22",
				Protocol:  "tcp",
				Action:    "accept",
			},
			{
				IPVersion: "ipv4",
				Name:      "allow-http",
				SrcIP:     "0.0.0.0/0",
				DstPort:   "80",
				Protocol:  "tcp",
				Action:    "accept",
			},
			{
				IPVersion: "ipv6",
				Name:      "allow-ssh-v6",
				SrcIP:     "::/0",
				DstPort:   "22",
				Protocol:  "tcp",
				Action:    "accept",
			},
		},
	},
}

func TestGetFirewall(t *testing.T) {
	t.Parallel()

	server := mockServer()
	defer server.Close()

	client := client.New(&client.ProviderConfig{
		Username: testUsername,
		Password: testPassword,
		BaseURL:  server.URL,
	})

	firewall, err := client.GetFirewall(context.Background(), testFirewall.IP)
	if err != nil {
		t.Errorf("GetFirewall() error: %v", err)
	}

	if testFirewall.IP != firewall.IP {
		t.Errorf("IP: want %v, got %v", testFirewall.IP, firewall.IP)
	}

	if testFirewall.WhitelistHetznerServices != firewall.WhitelistHetznerServices {
		t.Errorf(
			"WhitelistHetznerServices: want %t, got %t",
			testFirewall.WhitelistHetznerServices,
			firewall.WhitelistHetznerServices,
		)
	}

	if testFirewall.Status != firewall.Status {
		t.Errorf("Status: want %v, got %v", testFirewall.Status, firewall.Status)
	}

	if len(testFirewall.Rules.Input) != len(firewall.Rules.Input) {
		t.Errorf(
			"Rules length: want %d, got %d",
			len(testFirewall.Rules.Input),
			len(firewall.Rules.Input),
		)
	}

	for i, wantRule := range testFirewall.Rules.Input {
		gotRule := firewall.Rules.Input[i]
		if wantRule.Name != gotRule.Name {
			t.Errorf("Rule[%d] Name: want %v, got %v", i, wantRule.Name, gotRule.Name)
		}

		if wantRule.SrcIP != gotRule.SrcIP {
			t.Errorf("Rule[%d] SrcIP: want %v, got %v", i, wantRule.SrcIP, gotRule.SrcIP)
		}

		if wantRule.DstPort != gotRule.DstPort {
			t.Errorf(
				"Rule[%d] DstPort: want %v, got %v",
				i,
				wantRule.DstPort,
				gotRule.DstPort,
			)
		}

		if wantRule.Protocol != gotRule.Protocol {
			t.Errorf(
				"Rule[%d] Protocol: want %v, got %v",
				i,
				wantRule.Protocol,
				gotRule.Protocol,
			)
		}

		if wantRule.Action != gotRule.Action {
			t.Errorf("Rule[%d] Action: want %v, got %v", i, wantRule.Action, gotRule.Action)
		}
	}
}

func TestSetFirewall(t *testing.T) {
	t.Parallel()

	server := mockServer()
	defer server.Close()

	client := client.New(&client.ProviderConfig{
		Username: testUsername,
		Password: testPassword,
		BaseURL:  server.URL,
	})

	err := client.SetFirewall(context.Background(), testFirewall)
	if err != nil {
		t.Errorf("SetFirewall() error: %v", err)
	}
}

func TestSetFirewallIPv6(t *testing.T) {
	t.Parallel()

	server := mockServer()
	defer server.Close()

	client := client.New(&client.ProviderConfig{
		Username: testUsername,
		Password: testPassword,
		BaseURL:  server.URL,
	})

	err := client.SetFirewall(context.Background(), testFirewallIPv6)
	if err != nil {
		t.Errorf("SetFirewall() error: %v", err)
	}
}
