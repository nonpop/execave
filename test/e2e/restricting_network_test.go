package e2e_test

import (
	"fmt"
	"net"
	"testing"
)

// TestE2E_RestrictingNetwork_RunCommandWithNoNetworkAccess tests that without any net rules,
// HTTP-proxy-aware clients receive 403 from the deny-all proxy.
func TestE2E_RestrictingNetwork_RunCommandWithNoNetworkAccess(t *testing.T) {
	s := newScenario(t)
	s.givenCurl()

	s.givenRules()

	// No net rules → proxy starts with deny-all rule set; curl (proxy-aware) gets 403.
	s.whenRun("curl", "-si", "http://example.com/")

	s.thenStdoutContains("403")
}

// TestE2E_RestrictingNetwork_AllowSpecificHTTPSEndpoints tests that an allowed HTTPS endpoint
// is accessible through the proxy while other endpoints are denied.
func TestE2E_RestrictingNetwork_AllowSpecificHTTPSEndpoints(t *testing.T) {
	s := newScenario(t)
	s.givenCurl()

	srv := s.givenHTTPSServer("HTTPS_ALLOWED")

	s.givenRules("net:http:" + srv.addr())

	// Allowed endpoint succeeds
	s.whenRun("curl", "-sk", fmt.Sprintf("https://%s/", srv.hostPort()))

	s.thenExitCode(0)
	s.thenStdoutContains("HTTPS_ALLOWED")

	// Non-allowed endpoint denied
	s.whenRun("curl", "-sk", "--max-time", "5", "https://192.0.2.1:443/")

	s.thenExitCodeNonZero()
}

// TestE2E_RestrictingNetwork_AllowSpecificHTTPEndpoints tests that an allowed plain HTTP endpoint
// is accessible through the proxy while other endpoints are denied.
func TestE2E_RestrictingNetwork_AllowSpecificHTTPEndpoints(t *testing.T) {
	s := newScenario(t)
	s.givenCurl()

	srv := s.givenHTTPServer("HTTP_ALLOWED")

	s.givenRules("net:http:" + srv.addr())

	// Allowed endpoint succeeds
	s.whenRun("curl", "-s", fmt.Sprintf("http://%s/", srv.hostPort()))

	s.thenExitCode(0)
	s.thenStdoutContains("HTTP_ALLOWED")

	// Non-allowed endpoint denied
	s.whenRun("curl", "-sf", "--max-time", "5", "http://192.0.2.1/")

	s.thenExitCodeNonZero()
}

// TestE2E_RestrictingNetwork_BlockSpecificDomainWithinWildcardAllow tests that a more specific
// deny rule overrides a broader allow rule.
func TestE2E_RestrictingNetwork_BlockSpecificDomainWithinWildcardAllow(t *testing.T) {
	s := newScenario(t)
	s.givenCurl()

	_, allowedPort := testHTTPServer(t, "ALLOWED_ENDPOINT")
	_, blockedPort := testHTTPServer(t, "should not see this")

	s.givenRules(
		"net:http:127.0.0.0/8:*",
		"net:none:127.0.0.1/32:"+blockedPort,
	)

	s.whenRun("curl", "-s", fmt.Sprintf("http://127.0.0.1:%s/", allowedPort))

	s.thenExitCode(0)
	s.thenStdoutContains("ALLOWED_ENDPOINT")

	s.whenRun("curl", "-sf", "--max-time", "5", fmt.Sprintf("http://127.0.0.1:%s/", blockedPort))

	s.thenExitCodeNonZero()
}

// TestE2E_RestrictingNetwork_BlockSpecificIPWithinCIDRAllow tests that a longer CIDR prefix
// deny rule overrides a shorter CIDR prefix allow rule.
func TestE2E_RestrictingNetwork_BlockSpecificIPWithinCIDRAllow(t *testing.T) {
	s := newScenario(t)
	s.givenCurl()

	host, port := testHTTPServer(t, "should not see this")

	s.givenRules(
		"net:http:127.0.0.0/8:"+port,
		fmt.Sprintf("net:none:%s/32:%s", host, port),
	)

	s.whenRun("curl", "-sf", "--max-time", "5",
		"http://"+net.JoinHostPort(host, port)+"/")

	s.thenExitCodeNonZero()
}

// TestE2E_RestrictingNetwork_DirectTCPConnectionsFail tests that processes ignoring HTTP_PROXY
// cannot make direct TCP connections because the sandbox has no NIC.
func TestE2E_RestrictingNetwork_DirectTCPConnectionsFail(t *testing.T) {
	s := newScenario(t)
	s.givenPython3()

	s.givenRules("net:http:192.0.2.1:443")

	s.whenRun("python3", "-c",
		"import socket; s=socket.socket(); s.settimeout(2); s.connect(('1.1.1.1', 80))")

	s.thenExitCodeNonZero()
}

// TestE2E_RestrictingNetwork_UDPTrafficBlocked tests that UDP traffic is blocked because
// the sandbox has no network interface.
func TestE2E_RestrictingNetwork_UDPTrafficBlocked(t *testing.T) {
	s := newScenario(t)
	s.givenPython3()

	s.givenRules("net:http:192.0.2.1:443")

	s.whenRun("python3", "-c",
		"import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(2); s.sendto(b'test', ('1.1.1.1', 53))")

	s.thenExitCodeNonZero()
}

// TestE2E_RestrictingNetwork_ExitCodePreservedWithNetRules tests that the tunnel and proxy
// layers do not swallow the sandboxed command's exit code.
func TestE2E_RestrictingNetwork_ExitCodePreservedWithNetRules(t *testing.T) {
	s := newScenario(t)

	s.givenRules("net:http:127.0.0.1:*")

	s.whenRun("sh", "-c", "exit 42")

	s.thenExitCode(42)
}

// TestE2E_RestrictingNetwork_WildcardPortAccess tests that a wildcard port rule allows
// access on any port.
func TestE2E_RestrictingNetwork_WildcardPortAccess(t *testing.T) {
	s := newScenario(t)
	s.givenCurl()

	srv := s.givenHTTPServer("WILDCARD_PORT_OK")

	s.givenRules(fmt.Sprintf("net:http:%s:*", srv.host))

	s.whenRun("curl", "-s", fmt.Sprintf("http://%s/", srv.hostPort()))

	s.thenExitCode(0)
	s.thenStdoutContains("WILDCARD_PORT_OK")
}
