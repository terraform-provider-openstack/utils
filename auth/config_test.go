package auth_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/terraform-provider-openstack/utils/v2/auth"
)

func TestCloudsYAMLBackfillsAuthURL(t *testing.T) {
	dir := t.TempDir()
	yaml := `
clouds:
  foo:
    auth:
      auth_url: https://keystone.example/v3
      token: dummy-token
    region_name: RegionOne
`
	path := filepath.Join(dir, "clouds.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatalf("write clouds.yaml: %v", err)
	}

	t.Setenv("OS_CLIENT_CONFIG_FILE", path)
	t.Setenv("OS_AUTH_URL", "") // keep env empty

	cfg := &auth.Config{
		Cloud: "foo",
		// IdentityEndpoint is omitted to trigger backfill
	}

	_ = cfg.LoadAndValidate(context.Background())

	got := cfg.IdentityEndpoint
	want := "https://keystone.example/v3"
	if got != want {
		t.Fatalf("expected IdentityEndpoint %q from clouds.yaml, got %q", want, got)
	}
}
