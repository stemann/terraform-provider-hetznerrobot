package rdns

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/yellowhat/terraform-provider-hetznerrobot/internal/client"
)

// DataSourceType is the type name of the Hetzner Robot rDNS data source.
const DataSourceType = "hetznerrobot_rdns"

// DataSource defines the rdns terraform data source.
func DataSource() *schema.Resource {
	return &schema.Resource{
		Description: "Reads the PTR (reverse DNS) record for a Hetzner Robot IPv4 or IPv6 address.",
		ReadContext: dataSourceRead,
		Schema: map[string]*schema.Schema{
			"ip": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The IPv4 or IPv6 address to look up.",
			},
			"ptr": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The PTR (hostname) currently associated with the address. Empty if no PTR is set.",
			},
		},
	}
}

func dataSourceRead(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	hClient, ok := meta.(*client.HetznerRobotClient)
	if !ok {
		return diag.Errorf("invalid client type")
	}

	ip := d.Get("ip").(string)

	rec, err := hClient.FetchRDNS(ctx, ip)
	if err != nil && !errors.Is(err, client.ErrRDNSNotFound) {
		return diag.FromErr(fmt.Errorf("failed to read rdns for %s: %w", ip, err))
	}

	err = d.Set("ptr", rec.PTR)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error setting ptr attribute: %w", err))
	}

	d.SetId(ip)

	return nil
}
