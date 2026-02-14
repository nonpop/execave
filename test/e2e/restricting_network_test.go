package e2e_test

import (
	"fmt"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestE2E_RestrictingNetwork_RunCommandWithNoNetworkAccess tests that without any net rules,
// the sandbox has no network interface and all connections fail.
func TestE2E_RestrictingNetwork_RunCommandWithNoNetworkAccess(t *testing.T) {
	failIfNoBwrap(t)
	failIfNoPython3(t)

	configPath := writeConfig(t, systemPaths())

	// No net rules → no NIC, TCP connection fails
	result := runExecave(t, "", "--config", configPath, "--",
		"python3", "-c",
		"import socket; s=socket.socket(); s.settimeout(2); s.connect(('1.1.1.1', 80))")

	assert.NotEqual(t, 0, result.ExitCode)
}

// TestE2E_RestrictingNetwork_AllowSpecificHTTPSEndpoints tests that an allowed HTTPS endpoint
// is accessible through the proxy while other endpoints are denied.
func TestE2E_RestrictingNetwork_AllowSpecificHTTPSEndpoints(t *testing.T) {
	failIfNoBwrap(t)
	failIfNoCurl(t)

	host, port := testHTTPSServer(t, "HTTPS_ALLOWED")

	rules := append(systemPaths(),
		fmt.Sprintf("net:https:%s:%s", host, port),
	)
	configPath := writeConfig(t, rules)

	// Allowed endpoint succeeds
	result := runExecave(t, "", "--config", configPath, "--",
		"curl", "-sk", fmt.Sprintf("https://%s/", net.JoinHostPort(host, port)))

	assertExitCode(t, result, 0)
	assert.Contains(t, result.Stdout, "HTTPS_ALLOWED")

	// Non-allowed endpoint denied
	result = runExecave(t, "", "--config", configPath, "--",
		"curl", "-sk", "--max-time", "5", "https://192.0.2.1:443/")

	assert.NotEqual(t, 0, result.ExitCode)
}

// TestE2E_RestrictingNetwork_AllowSpecificHTTPEndpoints tests that an allowed plain HTTP endpoint
// is accessible through the proxy while other endpoints are denied.
func TestE2E_RestrictingNetwork_AllowSpecificHTTPEndpoints(t *testing.T) {
	failIfNoBwrap(t)
	failIfNoCurl(t)

	host, port := testHTTPServer(t, "HTTP_ALLOWED")

	rules := append(systemPaths(),
		fmt.Sprintf("net:http:%s:%s", host, port),
	)
	configPath := writeConfig(t, rules)

	// Allowed endpoint succeeds
	result := runExecave(t, "", "--config", configPath, "--",
		"curl", "-s", fmt.Sprintf("http://%s/", net.JoinHostPort(host, port)))

	assertExitCode(t, result, 0)
	assert.Contains(t, result.Stdout, "HTTP_ALLOWED")

	// Non-allowed endpoint denied
	result = runExecave(t, "", "--config", configPath, "--",
		"curl", "-sf", "--max-time", "5", "http://192.0.2.1/")

	assert.NotEqual(t, 0, result.ExitCode)
}

// TestE2E_RestrictingNetwork_BlockSpecificDomainWithinWildcardAllow tests that a more specific
// deny rule overrides a broader allow rule. Domain wildcards (*.example.com) cannot resolve to
// local test servers, so we test the same specificity concept with CIDR rules.
func TestE2E_RestrictingNetwork_BlockSpecificDomainWithinWildcardAllow(t *testing.T) {
	failIfNoBwrap(t)
	failIfNoCurl(t)

	_, allowedPort := testHTTPServer(t, "ALLOWED_ENDPOINT")
	_, blockedPort := testHTTPServer(t, "should not see this")

	// Broad CIDR+wildcard port allow, specific IP+port deny
	rules := append(systemPaths(),
		"net:http:127.0.0.0/8:*",
		"net:none:127.0.0.1/32:"+blockedPort,
	)
	configPath := writeConfig(t, rules)

	// Allowed: broad CIDR matches, no specific deny for this port
	result := runExecave(t, "", "--config", configPath, "--",
		"curl", "-s", fmt.Sprintf("http://127.0.0.1:%s/", allowedPort))

	assertExitCode(t, result, 0)
	assert.Contains(t, result.Stdout, "ALLOWED_ENDPOINT")

	// Blocked: specific /32 deny overrides broad /8 allow
	result = runExecave(t, "", "--config", configPath, "--",
		"curl", "-sf", "--max-time", "5", fmt.Sprintf("http://127.0.0.1:%s/", blockedPort))

	assert.NotEqual(t, 0, result.ExitCode)
}

// TestE2E_RestrictingNetwork_BlockSpecificIPWithinCIDRAllow tests that a longer CIDR prefix
// deny rule overrides a shorter CIDR prefix allow rule.
func TestE2E_RestrictingNetwork_BlockSpecificIPWithinCIDRAllow(t *testing.T) {
	failIfNoBwrap(t)
	failIfNoCurl(t)

	host, port := testHTTPServer(t, "should not see this")

	// Broad /8 allow, specific /32 deny
	rules := append(systemPaths(),
		"net:http:127.0.0.0/8:"+port,
		fmt.Sprintf("net:none:%s/32:%s", host, port),
	)
	configPath := writeConfig(t, rules)

	// /32 deny beats /8 allow
	result := runExecave(t, "", "--config", configPath, "--",
		"curl", "-sf", "--max-time", "5", fmt.Sprintf("http://%s/", net.JoinHostPort(host, port)))

	assert.NotEqual(t, 0, result.ExitCode)
}

// TestE2E_RestrictingNetwork_DirectTCPConnectionsFail tests that processes ignoring HTTP_PROXY
// cannot make direct TCP connections because the sandbox has no NIC.
func TestE2E_RestrictingNetwork_DirectTCPConnectionsFail(t *testing.T) {
	failIfNoBwrap(t)
	failIfNoPython3(t)

	// Net rules present, but process bypasses proxy
	rules := append(systemPaths(), "net:https:192.0.2.1:443")
	configPath := writeConfig(t, rules)

	result := runExecave(t, "", "--config", configPath, "--",
		"python3", "-c",
		"import socket; s=socket.socket(); s.settimeout(2); s.connect(('1.1.1.1', 80))")

	assert.NotEqual(t, 0, result.ExitCode)
}

// TestE2E_RestrictingNetwork_UDPTrafficBlocked tests that UDP traffic is blocked because
// the sandbox has no network interface.
func TestE2E_RestrictingNetwork_UDPTrafficBlocked(t *testing.T) {
	failIfNoBwrap(t)
	failIfNoPython3(t)

	rules := append(systemPaths(), "net:https:192.0.2.1:443")
	configPath := writeConfig(t, rules)

	result := runExecave(t, "", "--config", configPath, "--",
		"python3", "-c",
		"import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(2); s.sendto(b'test', ('1.1.1.1', 53))")

	assert.NotEqual(t, 0, result.ExitCode)
}

// TestE2E_RestrictingNetwork_ExitCodePreservedWithNetRules tests that the tunnel and proxy
// layers do not swallow the sandboxed command's exit code.
func TestE2E_RestrictingNetwork_ExitCodePreservedWithNetRules(t *testing.T) {
	failIfNoBwrap(t)

	rules := append(systemPaths(), "net:http:127.0.0.1:*")
	configPath := writeConfig(t, rules)

	result := runExecave(t, "", "--config", configPath, "--",
		"sh", "-c", "exit 42")

	assertExitCode(t, result, 42)
}

// TestE2E_RestrictingNetwork_WildcardPortAccess tests that a wildcard port rule allows
// access on any port.
func TestE2E_RestrictingNetwork_WildcardPortAccess(t *testing.T) {
	failIfNoBwrap(t)
	failIfNoCurl(t)

	host, port := testHTTPServer(t, "WILDCARD_PORT_OK")

	rules := append(systemPaths(),
		fmt.Sprintf("net:http:%s:*", host),
	)
	configPath := writeConfig(t, rules)

	result := runExecave(t, "", "--config", configPath, "--",
		"curl", "-s", fmt.Sprintf("http://%s/", net.JoinHostPort(host, port)))

	assertExitCode(t, result, 0)
	assert.Contains(t, result.Stdout, "WILDCARD_PORT_OK")
}
