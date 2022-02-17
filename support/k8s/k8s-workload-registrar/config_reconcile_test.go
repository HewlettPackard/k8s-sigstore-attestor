package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
)

var (
	testMinimalReconcileConfig = `
		trust_domain = "TRUSTDOMAIN"
		cluster = "CLUSTER"
		server_socket_path = "SOCKETPATH"
		mode = "reconcile"
		check_signature_enabled = true
	`
)

func TestLoadModeReconcile(t *testing.T) {
	require := require.New(t)

	dir := spiretest.TempDir(t)

	confPath := filepath.Join(dir, "test.conf")

	_, err := LoadMode(confPath)
	require.Error(err)
	require.Contains(err.Error(), "unable to load configuration:")

	err = os.WriteFile(confPath, []byte(testMinimalReconcileConfig), 0600)
	require.NoError(err)

	config, err := LoadMode(confPath)
	require.NoError(err)

	require.Equal(&ReconcileMode{
		CommonMode: CommonMode{
			ServerSocketPath:      "SOCKETPATH",
			ServerAddress:         "unix://SOCKETPATH",
			TrustDomain:           "TRUSTDOMAIN",
			Cluster:               "CLUSTER",
			LogLevel:              defaultLogLevel,
			Mode:                  "reconcile",
			DisabledNamespaces:    []string{"kube-system", "kube-public"},
			CheckSignatureEnabled: true,
		},
		MetricsAddr:    defaultMetricsAddr,
		LeaderElection: false,
		ControllerName: defaultControllerName,
		AddPodDNSNames: false,
		ClusterDNSZone: defaultClusterDNSZone,
	}, config)
}
