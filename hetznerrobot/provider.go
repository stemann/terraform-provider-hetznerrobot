// Package hetznerrobot provides the HetznerRobot Terraform provider.
package hetznerrobot

import (
	"context"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/yellowhat/terraform-provider-hetznerrobot/internal/client"
	"github.com/yellowhat/terraform-provider-hetznerrobot/internal/firewall"
	"github.com/yellowhat/terraform-provider-hetznerrobot/internal/rdns"
	"github.com/yellowhat/terraform-provider-hetznerrobot/internal/server"
	"github.com/yellowhat/terraform-provider-hetznerrobot/internal/vswitch"
)

// Provider provides the HetznerRobot Terraform provider.
func Provider() *schema.Provider {
	return &schema.Provider{
		Schema: map[string]*schema.Schema{
			"username": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Hetzner Robot API username.",
				DefaultFunc: schema.EnvDefaultFunc("HETZNERROBOT_USERNAME", nil),
			},
			"password": {
				Type:        schema.TypeString,
				Required:    true,
				Sensitive:   true,
				Description: "Hetzner Robot API password.",
				DefaultFunc: schema.EnvDefaultFunc("HETZNERROBOT_PASSWORD", nil),
			},
			"url": {
				Type:     schema.TypeString,
				Optional: true,
				DefaultFunc: schema.EnvDefaultFunc(
					"HETZNERROBOT_URL",
					"https://robot-ws.your-server.de",
				),
				Description: "Base URL for the Hetzner Robot API.",
			},
		},
		ResourcesMap: map[string]*schema.Resource{
			"hetznerrobot_firewall":        firewall.Resource(),
			"hetznerrobot_os_rescue":       server.ResourceOSRescue(),
			"hetznerrobot_rdns":            rdns.Resource(),
			"hetznerrobot_vswitch":         vswitch.Resource(),
			"hetznerrobot_vswitch_servers": vswitch.ServersResource(),
		},
		DataSourcesMap: map[string]*schema.Resource{
			"hetznerrobot_rdns":    rdns.DataSource(),
			"hetznerrobot_server":  server.DataSourceServers(),
			"hetznerrobot_vswitch": vswitch.DataSource(),
		},
		ConfigureContextFunc: providerConfigure,
	}
}

// providerConfigure configures the HetznerRobot Terraform provider.
func providerConfigure(_ context.Context, d *schema.ResourceData) (any, diag.Diagnostics) {
	var diags diag.Diagnostics

	username := d.Get("username").(string)
	password := d.Get("password").(string)
	url := d.Get("url").(string)

	if username == "" || password == "" {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Missing credentials",
			Detail:   "Both username and password must be provided.",
		})

		return nil, diags
	}

	config := &client.ProviderConfig{
		Username: username,
		Password: password,
		BaseURL:  url,
	}
	client := client.New(config)

	return client, diags
}
