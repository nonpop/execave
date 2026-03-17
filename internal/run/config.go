package run

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/nonpop/execave/internal/binutil"
	"github.com/nonpop/execave/internal/config"
	"github.com/nonpop/execave/internal/sandbox"
)

// RuntimeConfig holds the resolved runtime configuration from [LoadRuntimeConfig].
type RuntimeConfig struct {
	Config       *config.Config // Merged, validated configuration.
	TunnelBinary string         // Path to the execave binary used as the tunnel.
	UDSPath      string         // Path to the proxy Unix domain socket.
}

// LoadRuntimeConfig loads config, resolves binaries, and creates the proxy
// directory. The returned cleanup removes the proxy directory; defer it.
func LoadRuntimeConfig(cfgPath string) (*RuntimeConfig, func(), error) {
	tunnelBinary, err := os.Executable()
	if err != nil {
		return nil, nil, fmt.Errorf("resolve executable path: %w", err)
	}

	proxyDir, err := CreateProxyDir()
	if err != nil {
		return nil, nil, err
	}
	cleanup := func() { _ = os.RemoveAll(proxyDir) }
	udsPath := filepath.Join(proxyDir, "proxy.sock")

	// Detect ELF interpreter from bwrap to auto-mount the dynamic linker.
	// bwrap is mandatory and re-validated at sandbox launch; if unavailable
	// here, skip interpreter auto-detection only.
	var interpPath string
	if bwrapPath, resolveErr := binutil.ResolveBwrap(); resolveErr == nil {
		interpPath = binutil.InterpreterPath(bwrapPath)
	}
	managedPaths := sandbox.ManagedDirs()

	cfg, err := config.Load(cfgPath, managedPaths, interpPath, tunnelBinary, udsPath)
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("load config from %s: %w", cfgPath, err)
	}

	return &RuntimeConfig{
		Config:       cfg,
		TunnelBinary: tunnelBinary,
		UDSPath:      udsPath,
	}, cleanup, nil
}

// CreateProxyDir creates a temporary directory for the proxy UDS. It uses
// XDG_RUNTIME_DIR when set, falling back to /run/user/<uid>. The caller must
// remove the directory when done.
func CreateProxyDir() (string, error) {
	runtimeDir := os.Getenv("XDG_RUNTIME_DIR")
	if runtimeDir == "" {
		runtimeDir = fmt.Sprintf("/run/user/%d", os.Getuid())
	}
	dir, err := os.MkdirTemp(runtimeDir, "execave-*")
	if err != nil {
		return "", fmt.Errorf("create proxy dir: %w", err)
	}
	return dir, nil
}
