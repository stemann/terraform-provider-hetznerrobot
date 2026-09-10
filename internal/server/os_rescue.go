package server

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/yellowhat/terraform-provider-hetznerrobot/internal/client"
)

const (
	// ResourceOSRescueType is the type name of the Hetzner Robot OS Rescue resource.
	ResourceOSRescueType = "hetznerrobot_os_rescue"
	waitMin              = 3
	downWaitMin          = 1
	retryAfterSec        = 10
	dialTimeoutSec       = 5
)

// ResourceOSRescue defines the os_rescue terraform resource.
func ResourceOSRescue() *schema.Resource {
	return &schema.Resource{
		Description: `Reboot a server into Hetzner Robot rescue system:

1. activate the Hetzner Robot rescue system

2. issue the reset (hw by default, sw for a Ctrl+Alt+Del)

3. wait for the installed OS to stop answering on port 22

4. wait for the rescue system's SSH port to come up

5. scan the rescue system's SSH host keys and expose them

6. rename the server

Updates only handle server_name changes; all other fields are effectively immutable.
Read and Delete are no-ops, so destroying the resource does not deactivate rescue mode or reboot the server back to its installed OS.`,
		CreateContext: resourceOSRescueCreate,
		ReadContext:   schema.NoopContext,
		UpdateContext: resourceOSRescueUpdate,
		DeleteContext: schema.NoopContext,
		Schema: map[string]*schema.Schema{
			"server_name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Name to assign to the server after the rescue system is reachable. The only field whose change is honored by Update.",
			},
			"server_id": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Server ID (Hetzner server number).",
			},
			"rescue_os": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "linux",
				Description: "Operating system for rescue mode (e.g. linux, freebsd).",
			},
			"ssh_keys": {
				Type:     schema.TypeList,
				Optional: true,
				Description: "List of public SSH keys to install in the rescue system's authorized_keys. " +
					"If non-empty, the rescue system disables password authentication and `ssh_password` will be empty. " +
					"If left empty, Hetzner generates a one-shot root password (returned in `ssh_password`).",
				Elem: &schema.Schema{Type: schema.TypeString},
			},
			"reboot": {
				Type:         schema.TypeString,
				Optional:     true,
				Default:      "hw",
				ForceNew:     true,
				ValidateFunc: validation.StringInSlice([]string{"hw", "sw"}, false),
				Description: `Reset type used to boot into the rescue system after activation:
* hw performs a hardware reset (equivalent to pressing the reset button on the chassis)
* sw sends Ctrl+Alt+Del to the running OS for a clean reboot (Linux/Unix only)

Only takes effect on Create — changing this forces recreate.`,
			},
			"ip": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Public IPv4 of the server.",
			},
			"ssh_password": {
				Type:        schema.TypeString,
				Computed:    true,
				Sensitive:   true,
				Description: "One-shot root password for the rescue system. Set only when ssh_keys is empty; otherwise this is empty and you authenticate with one of the listed keys.",
			},
			"host_key_fingerprints": {
				Type:        schema.TypeMap,
				Computed:    true,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Description: "MD5 fingerprints of the host keys the rescue system presented, keyed by SSH key algorithm (e.g. \"ssh-ed25519\"). Computed from the scanned keys; the Hetzner API reports no fingerprints for the rescue system.",
			},
			"host_keys": {
				Type:     schema.TypeMap,
				Computed: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
				Description: "Host keys the rescue system presented, in authorized_keys format, keyed by SSH key algorithm (e.g. \"ssh-ed25519\"). " +
					"Each value is suitable to feed directly into a Terraform connection block, e.g. host_key = self.host_keys[\"ssh-ed25519\"]. " +
					"Trusted on first use: there is nothing to verify them against.",
			},
		},
	}
}

func resourceOSRescueCreate(
	ctx context.Context,
	d *schema.ResourceData,
	meta any,
) diag.Diagnostics {
	hClient, ok := meta.(*client.HetznerRobotClient)
	if !ok {
		return diag.Errorf("invalid client type")
	}

	serverName := d.Get("server_name").(string)
	serverID := d.Get("server_id").(string)
	rescueOS := d.Get("rescue_os").(string)
	sshKeys := parseSSHKeys(d.Get("ssh_keys").([]any))

	rescueResp, err := hClient.EnableRescueMode(ctx, serverID, rescueOS, sshKeys)
	if err != nil {
		return diag.FromErr(
			fmt.Errorf("failed to enable rescue mode for server %s: %w", serverID, err),
		)
	}

	ip := rescueResp.Rescue.ServerIP
	if ip == "" {
		return diag.Errorf("rescue mode for server %s was activated without a server IP", serverID)
	}

	err = hClient.RebootServer(ctx, serverID, d.Get("reboot").(string))
	if err != nil {
		return diag.FromErr(fmt.Errorf("failed to reset server %s: %w", serverID, err))
	}

	waitForSSHDown(ctx, ip, downWaitMin*time.Minute, retryAfterSec*time.Second)

	err = waitForSSH(ctx, ip, waitMin*time.Minute, retryAfterSec*time.Second)
	if err != nil {
		return diag.FromErr(fmt.Errorf("SSH not available on server %s: %w", serverID, err))
	}

	err = finalizeOSRescue(ctx, d, hClient, serverID, serverName, rescueResp)
	if err != nil {
		return diag.FromErr(
			fmt.Errorf("failed to finalize rescue for server %s: %w", serverID, err),
		)
	}

	d.SetId(serverID)

	unverified := diag.Diagnostic{
		Severity: diag.Warning,
		Summary:  "Rescue system host keys are unverified",
		Detail: "host_keys and host_key_fingerprints hold what the rescue system presented on first " +
			"contact. The Hetzner Robot API reports no host-key fingerprints for the rescue system, " +
			"so there is nothing to verify them against.",
	}

	return diag.Diagnostics{unverified}
}

func parseSSHKeys(raw []any) []string {
	keys := make([]string, 0, len(raw))
	for _, key := range raw {
		keys = append(keys, key.(string))
	}

	return keys
}

func finalizeOSRescue(
	ctx context.Context,
	d *schema.ResourceData,
	hClient *client.HetznerRobotClient,
	serverID, serverName string,
	rescueResp *client.HetznerRescueResponse,
) error {
	err := captureRescueHostKeys(ctx, d, rescueResp.Rescue.ServerIP)
	if err != nil {
		return fmt.Errorf("host key capture failed: %w", err)
	}

	_, err = hClient.RenameServer(ctx, serverID, serverName)
	if err != nil {
		return fmt.Errorf("failed to rename server: %w", err)
	}

	err = d.Set("ip", rescueResp.Rescue.ServerIP)
	if err != nil {
		return fmt.Errorf("error setting ip attribute: %w", err)
	}

	err = d.Set("ssh_password", rescueResp.Rescue.Password)
	if err != nil {
		return fmt.Errorf("error setting ssh_password attribute: %w", err)
	}

	return nil
}

func resourceOSRescueUpdate(
	ctx context.Context,
	d *schema.ResourceData,
	meta any,
) diag.Diagnostics {
	hClient, ok := meta.(*client.HetznerRobotClient)
	if !ok {
		return diag.Errorf("invalid client type")
	}

	serverName := d.Get("server_name").(string)
	serverID := d.Get("server_id").(string)

	serverInfo, err := hClient.FetchServerByID(ctx, serverID)
	if err != nil {
		return diag.FromErr(fmt.Errorf("failed to fetch server %s info: %w", serverID, err))
	}

	if serverName != serverInfo.ServerName {
		_, err := hClient.RenameServer(ctx, serverID, serverName)
		if err != nil {
			return diag.FromErr(fmt.Errorf("failed to rename server %s: %w", serverID, err))
		}
	}

	return nil
}

// dialSSH reports whether anything accepts a TCP connection on ip:22.
func dialSSH(ctx context.Context, ip string) bool {
	//exhaustruct:ignore
	dialer := &net.Dialer{
		Timeout: dialTimeoutSec * time.Second,
	}

	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, "22"))
	if err != nil {
		return false
	}

	_ = conn.Close()

	return true
}

func waitForSSH(
	ctx context.Context,
	ip string,
	timeout time.Duration,
	interval time.Duration,
) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if dialSSH(ctx, ip) {
			return nil
		}

		time.Sleep(interval)
	}

	return fmt.Errorf("SSH not available on %s after %v", ip, timeout)
}

// waitForSSHDown waits for the installed OS to stop answering on port 22.
func waitForSSHDown(
	ctx context.Context,
	ip string,
	timeout time.Duration,
	interval time.Duration,
) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if !dialSSH(ctx, ip) {
			return
		}

		time.Sleep(interval)
	}
}
