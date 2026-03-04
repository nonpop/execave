package run

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/nonpop/execave/internal/binutil"
	"github.com/nonpop/execave/internal/config"
	"github.com/nonpop/execave/internal/sandbox"
)

// RuntimeConfig holds the resolved runtime configuration returned by LoadRuntimeConfig.
type RuntimeConfig struct {
	// Config is the merged, validated configuration.
	Config *config.Config
	// TunnelBinary is the path to the execave binary used as the tunnel.
	TunnelBinary string
	// UDSPath is the path to the proxy Unix domain socket.
	UDSPath string
}

// LoadRuntimeConfig loads and resolves the runtime configuration from cfgPath.
// It resolves the tunnel binary via os.Executable(), creates the proxy directory,
// auto-detects the dynamic linker from bwrap, and returns a RuntimeConfig.
// The returned cleanup function removes the proxy directory; the caller must defer it.
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

// CreateProxyDir creates a temporary directory under XDG_RUNTIME_DIR for the proxy UDS.
// XDG_RUNTIME_DIR must be set; returns an error if it is not.
// The caller is responsible for removing the directory when done.
func CreateProxyDir() (string, error) {
	runtimeDir := os.Getenv("XDG_RUNTIME_DIR")
	if runtimeDir == "" {
		return "", fmt.Errorf("create proxy dir: XDG_RUNTIME_DIR not set")
	}
	dir, err := os.MkdirTemp(runtimeDir, "execave-*")
	if err != nil {
		return "", fmt.Errorf("create proxy dir: %w", err)
	}
	return dir, nil
}
