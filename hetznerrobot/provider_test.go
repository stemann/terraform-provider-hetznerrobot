package hetznerrobot_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/yellowhat/terraform-provider-hetznerrobot/hetznerrobot"
	"github.com/yellowhat/terraform-provider-hetznerrobot/internal/firewall"
	"github.com/yellowhat/terraform-provider-hetznerrobot/internal/rdns"
	"github.com/yellowhat/terraform-provider-hetznerrobot/internal/server"
	"github.com/yellowhat/terraform-provider-hetznerrobot/internal/vswitch"
)

func TestProvider(t *testing.T) {
	t.Parallel()

	err := hetznerrobot.Provider().InternalValidate()
	if err != nil {
		t.Fatalf("err: %s", err)
	}
}

func TestProvider_Resources(t *testing.T) {
	t.Parallel()

	provider := hetznerrobot.Provider()
	expectedResources := []string{
		firewall.ResourceType,
		rdns.ResourceType,
		server.ResourceOSRescueType,
		vswitch.ResourceType,
		vswitch.ServersResourceType,
	}

	resources := provider.Resources()
	assert.Len(t, resources, len(expectedResources))

	for _, resource := range resources {
		assert.Contains(t, expectedResources, resource.Name)
	}
}

func TestProvider_DataSources(t *testing.T) {
	t.Parallel()

	provider := hetznerrobot.Provider()
	expectedDataSources := []string{
		rdns.DataSourceType,
		server.DataSourceType,
		vswitch.DataSourceType,
	}

	dataSources := provider.DataSources()
	assert.Len(t, dataSources, len(expectedDataSources))

	for _, datasource := range dataSources {
		assert.Contains(t, expectedDataSources, datasource.Name)
	}
}
