// Package rdns defines the rdns terraform resource and data source.
package rdns

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/yellowhat/terraform-provider-hetznerrobot/internal/client"
)

// ResourceType is the type name of the Hetzner Robot rDNS resource.
const ResourceType = "hetznerrobot_rdns"

// Resource defines the rdns terraform resource.
func Resource() *schema.Resource {
	return &schema.Resource{
		Description:   "Manages the PTR (reverse DNS) record for a Hetzner Robot IPv4 or IPv6 address.",
		CreateContext: create,
		ReadContext:   read,
		UpdateContext: update,
		DeleteContext: delete_,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: map[string]*schema.Schema{
			"ip": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "The IPv4 or IPv6 address to set the PTR for. Must be an address belonging to the account.",
			},
			"ptr": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The PTR (hostname) to associate with the address.",
			},
		},
	}
}

func create(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	hClient, ok := meta.(*client.HetznerRobotClient)
	if !ok {
		return diag.Errorf("invalid client type")
	}

	ip := d.Get("ip").(string)
	ptr := d.Get("ptr").(string)

	err := hClient.SetRDNS(ctx, ip, ptr)
	if err != nil {
		return diag.FromErr(fmt.Errorf("failed to set rdns for %s: %w", ip, err))
	}

	d.SetId(ip)

	return read(ctx, d, meta)
}

func read(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	hClient, ok := meta.(*client.HetznerRobotClient)
	if !ok {
		return diag.Errorf("invalid client type")
	}

	ip := d.Id()

	rec, err := hClient.FetchRDNS(ctx, ip)
	if err != nil {
		if errors.Is(err, client.ErrRDNSNotFound) {
			d.SetId("")

			return nil
		}

		return diag.FromErr(fmt.Errorf("failed to read rdns for %s: %w", ip, err))
	}

	err = d.Set("ip", rec.IP)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error setting ip attribute: %w", err))
	}

	err = d.Set("ptr", rec.PTR)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error setting ptr attribute: %w", err))
	}

	return nil
}

func update(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	hClient, ok := meta.(*client.HetznerRobotClient)
	if !ok {
		return diag.Errorf("invalid client type")
	}

	ip := d.Id()
	ptr := d.Get("ptr").(string)

	err := hClient.SetRDNS(ctx, ip, ptr)
	if err != nil {
		return diag.FromErr(fmt.Errorf("failed to update rdns for %s: %w", ip, err))
	}

	return read(ctx, d, meta)
}

//nolint:revive // delete is a Go builtin; trailing underscore avoids shadowing.
func delete_(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	hClient, ok := meta.(*client.HetznerRobotClient)
	if !ok {
		return diag.Errorf("invalid client type")
	}

	err := hClient.DeleteRDNS(ctx, d.Id())
	if err != nil {
		return diag.FromErr(fmt.Errorf("failed to delete rdns for %s: %w", d.Id(), err))
	}

	return nil
}
