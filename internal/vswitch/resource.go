package vswitch

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strconv"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/yellowhat/terraform-provider-hetznerrobot/internal/client"
)

const (
	// ResourceType is the type name of the Hetzner Robot vSwitch resource.
	ResourceType = "hetznerrobot_vswitch"
)

// Resource defines the vswitch terraform resource.
func Resource() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceCreate,
		ReadContext:   resourceRead,
		UpdateContext: resourceUpdate,
		DeleteContext: resourceDelete,

		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The name of the vSwitch.",
			},
			"vlan": {
				Type:        schema.TypeInt,
				Optional:    true,
				Computed:    true,
				Description: "The VLAN ID for the vSwitch. If not provided, one will be chosen randomly from [4000..4091].",
			},
			"servers": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "Server IDs to connect to the vSwitch.",
				Elem:        &schema.Schema{Type: schema.TypeInt},
			},
			"cancellation_date": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The cancellation date for the vSwitch. If not provided, defaults to 'now'.",
			},
			"incidents": {
				Type:        schema.TypeList,
				Computed:    true,
				Description: "List of warnings related to vSwitch.",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
		},
	}
}

func resourceCreate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	hClient, ok := meta.(*client.HetznerRobotClient)
	if !ok {
		return diag.Errorf("invalid client type")
	}

	name := d.Get("name").(string)

	var chosenVLAN int

	if vlan, vlanProvided := d.GetOk("vlan"); vlanProvided {
		chosenVLAN = vlan.(int)
	} else {
		freeVLAN, err := pickRandomFreeVLAN(ctx, hClient)
		if err != nil {
			return diag.FromErr(fmt.Errorf("failed to pick random free VLAN: %w", err))
		}

		chosenVLAN = freeVLAN

		err = d.Set("vlan", chosenVLAN)
		if err != nil {
			return diag.FromErr(fmt.Errorf("error setting vlan attribute: %w", err))
		}
	}

	vsw, err := hClient.CreateVSwitch(ctx, name, chosenVLAN)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error creating vSwitch: %w", err))
	}

	vswID := strconv.Itoa(vsw.ID)

	if servers, ok := d.GetOk("servers"); ok {
		serverIDs := parseServerIDs(servers.(*schema.Set))

		serverObjects := parseServerIDsToVSwitchServers(serverIDs)
		if len(serverObjects) > 0 {
			err := hClient.AddVSwitchServers(ctx, vswID, serverObjects)
			if err != nil {
				return diag.FromErr(fmt.Errorf("error adding servers to vSwitch: %w", err))
			}
		}
	}

	err = hClient.WaitForVSwitchReady(ctx, vswID)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error waiting for vSwitch readiness after create: %w", err))
	}

	d.SetId(strconv.Itoa(vsw.ID))

	return resourceRead(ctx, d, meta)
}

func resourceRead(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	hClient, ok := meta.(*client.HetznerRobotClient)
	if !ok {
		return diag.Errorf("invalid client type")
	}

	id := d.Id()

	vsw, err := hClient.FetchVSwitchByID(ctx, id)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error reading vSwitch: %w", err))
	}

	err = d.Set("name", vsw.Name)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error setting name attribute: %w", err))
	}

	err = d.Set("vlan", vsw.VLAN)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error setting vlan attribute: %w", err))
	}

	servers := flattenServers(vsw.Servers)

	err = d.Set("servers", servers)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error setting servers attribute: %w", err))
	}

	var incidents []string

	for _, server := range vsw.Servers {
		if server.Status == "failed" {
			message := fmt.Sprintf(
				"Server %d failed to connect. Please check in the Hetzner web interface.",
				server.ServerNumber,
			)
			incidents = append(incidents, message)
		}
	}

	err = d.Set("incidents", incidents)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error setting incidents attribute: %w", err))
	}

	return nil
}

func resourceUpdate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	hClient, ok := meta.(*client.HetznerRobotClient)
	if !ok {
		return diag.Errorf("invalid client type")
	}

	id := d.Id()
	name := d.Get("name").(string)
	vlan := d.Get("vlan").(int)

	var waitForReady bool

	if d.HasChange("name") || d.HasChange("vlan") {
		oldVlan, _ := d.GetChange("vlan")

		err := hClient.UpdateVSwitch(ctx, id, name, vlan)
		if err != nil {
			return diag.FromErr(fmt.Errorf("error updating vSwitch: %w", err))
		}

		if vlan != oldVlan.(int) {
			waitForReady = true
		}
	}

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

	return resourceRead(ctx, d, meta)
}

func manageServers(
	ctx context.Context,
	d *schema.ResourceData,
	hClient *client.HetznerRobotClient,
	id string,
) diag.Diagnostics {
	oldRaw, newRaw := d.GetChange("servers")
	oldServers := parseServerIDs(oldRaw.(*schema.Set))
	newServers := parseServerIDs(newRaw.(*schema.Set))

	toAdd, toRemove := diffServers(oldServers, newServers)

	if len(toRemove) > 0 {
		removeObjects := parseServerIDsToVSwitchServers(toRemove)

		err := hClient.RemoveVSwitchServers(ctx, id, removeObjects)
		if err != nil {
			return diag.FromErr(fmt.Errorf("error removing servers from vSwitch: %w", err))
		}
	}

	if len(toAdd) > 0 {
		addObjects := parseServerIDsToVSwitchServers(toAdd)

		err := hClient.AddVSwitchServers(ctx, id, addObjects)
		if err != nil {
			return diag.FromErr(fmt.Errorf("error adding servers to vSwitch: %w", err))
		}
	}

	return nil
}

func resourceDelete(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	hClient, ok := meta.(*client.HetznerRobotClient)
	if !ok {
		return diag.Errorf("invalid client type")
	}

	id := d.Id()

	cancellationDate := d.Get("cancellation_date").(string)
	if cancellationDate == "" {
		cancellationDate = "now"
	}

	err := hClient.DeleteVSwitch(ctx, id, cancellationDate)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error deleting vSwitch: %w", err))
	}

	d.SetId("")

	return nil
}

// helpers.
func parseServerIDs(servers *schema.Set) []int {
	result := make([]int, 0, servers.Len())
	for _, s := range servers.List() {
		result = append(result, s.(int))
	}

	return result
}

func parseServerIDsToVSwitchServers(serverIDs []int) []client.VSwitchServer {
	servers := make([]client.VSwitchServer, 0, len(serverIDs))

	for _, id := range serverIDs {
		server := client.VSwitchServer{
			ServerNumber:  id,
			ServerIP:      "",
			ServerIPv6Net: "",
			Status:        "",
		}
		servers = append(servers, server)
	}

	return servers
}

func flattenServers(servers []client.VSwitchServer) []int {
	result := make([]int, 0, len(servers))
	for _, s := range servers {
		result = append(result, s.ServerNumber)
	}

	sort.Ints(result)

	return result
}

func pickRandomFreeVLAN(ctx context.Context, c *client.HetznerRobotClient) (int, error) {
	vswitches, err := c.FetchAllVSwitches(ctx)
	if err != nil {
		return 0, fmt.Errorf("fetch all vswitches error: %w", err)
	}

	used := make(map[int]bool)
	for _, v := range vswitches {
		used[v.VLAN] = true
	}

	var free []int

	for vlan := 4000; vlan <= 4091; vlan++ {
		if !used[vlan] {
			free = append(free, vlan)
		}
	}

	if len(free) == 0 {
		return 0, errors.New("no free VLAN in [4000..4091], all are taken")
	}

	idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(free))))
	if err != nil {
		return 0, fmt.Errorf("generating a random index: %w", err)
	}

	return free[idx.Int64()], nil
}

func diffServers(oldList, newList []int) ([]int, []int) {
	oldMap := make(map[int]bool)
	newMap := make(map[int]bool)

	for _, id := range oldList {
		oldMap[id] = true
	}

	for _, id := range newList {
		newMap[id] = true
	}

	var toRemove []int

	for id := range oldMap {
		if !newMap[id] {
			toRemove = append(toRemove, id)
		}
	}

	var toAdd []int

	for id := range newMap {
		if !oldMap[id] {
			toAdd = append(toAdd, id)
		}
	}

	return toAdd, toRemove
}
