package vswitch

import (
	"context"
	"fmt"
	"strconv"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/yellowhat/terraform-provider-hetznerrobot/internal/client"
)

const (
	// ServersResourceType is the type name of the Hetzner Robot vSwitch Servers resource.
	ServersResourceType = "hetznerrobot_vswitch_servers"
)

// ServersResource defines the vswitch servers terraform resource.
func ServersResource() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceServersCreate,
		ReadContext:   resourceServersRead,
		UpdateContext: resourceServersUpdate,
		DeleteContext: resourceServersDelete,

		Schema: map[string]*schema.Schema{
			"vswitch_id": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Existing vSwitch ID.",
			},
			"servers": {
				Type:        schema.TypeSet,
				Required:    true,
				Description: "Server IDs to attach to the vSwitch.",
				Elem:        &schema.Schema{Type: schema.TypeInt},
			},
			"include_unmanaged": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Whether to include non-managed servers when reading the resource state.",
			},
		},
	}
}

func resourceServersCreate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	hClient, ok := meta.(*client.HetznerRobotClient)
	if !ok {
		return diag.Errorf("invalid client type")
	}

	vswID := d.Get("vswitch_id").(string)

	servers := d.Get("servers")
	serverIDs := parseServerIDs(servers.(*schema.Set))
	serverObjs := parseServerIDsToVSwitchServers(serverIDs)

	err := hClient.AddVSwitchServers(ctx, vswID, serverObjs)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error adding servers to vSwitch: %w", err))
	}

	err = hClient.WaitForVSwitchReady(ctx, vswID)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error waiting for vSwitch readiness after create: %w", err))
	}

	d.SetId(vswID)

	return resourceServersRead(ctx, d, meta)
}

func resourceServersRead(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	hClient, ok := meta.(*client.HetznerRobotClient)
	if !ok {
		return diag.Errorf("invalid client type")
	}

	id := d.Id()

	vsw, err := hClient.FetchVSwitchByID(ctx, id)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error reading vSwitch: %w", err))
	}

	vswID := strconv.Itoa(vsw.ID)

	err = d.Set("vswitch_id", vswID)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error setting vswitch_id attribute: %w", err))
	}

	if !d.Get("include_unmanaged").(bool) {
		return nil
	}

	servers := flattenServers(vsw.Servers)

	err = d.Set("servers", servers)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error setting servers attribute: %w", err))
	}

	return nil
}

func resourceServersUpdate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	hClient, ok := meta.(*client.HetznerRobotClient)
	if !ok {
		return diag.Errorf("invalid client type")
	}

	id := d.Id()

	var waitForReady bool

	if d.HasChange("servers") {
		if err := manageServers(ctx, d, hClient, id); err != nil {
			return err
		}

		waitForReady = true
	}

	if waitForReady {
		err := hClient.WaitForVSwitchReady(ctx, id)
		if err != nil {
			return diag.FromErr(
				fmt.Errorf("error waiting for vSwitch readiness after update: %w", err),
			)
		}
	}

	return resourceServersRead(ctx, d, meta)
}

func resourceServersDelete(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	hClient, ok := meta.(*client.HetznerRobotClient)
	if !ok {
		return diag.Errorf("invalid client type")
	}

	id := d.Id()
	servers := d.Get("servers")
	serverIDs := parseServerIDs(servers.(*schema.Set))
	serverObjs := parseServerIDsToVSwitchServers(serverIDs)

	err := hClient.RemoveVSwitchServers(ctx, id, serverObjs)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error removing servers from vSwitch: %w", err))
	}

	d.SetId("")

	return nil
}
