package e2e_test

import (
	"fmt"
	"net"
	"testing"
)

func Test_RestrictingNetwork_RunCommandWithNoNetworkAccess(t *testing.T) {
	// Without any net rules, HTTP-proxy-aware clients receive 403 from the deny-all proxy for
	// all request types.
	failIfNoCurl(t)

	for _, tt := range []struct {
		name string
		args []string
	}{
		{"http", []string{"curl", "-si", "http://example.com/"}},
		{"https_connect", []string{"curl", "-si", "--max-time", "5", "https://example.com/"}},
		{"http_ip_literal", []string{"curl", "-si", "http://192.0.2.1/"}},
		{"http_nonstandard_port", []string{"curl", "-si", "http://example.com:8080/"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := newScenario(t)
			s.givenRules() // no net rules → deny-all
			s.whenRun(tt.args...)
			s.thenStdoutContains("403")
		})
	}

	t.Run("http_with_host_no_proxy", func(t *testing.T) {
		// NO_PROXY/no_proxy from the host must be stripped so the sandbox command
		// still routes through the proxy and receives a clean 403.
		t.Setenv("NO_PROXY", "*")
		t.Setenv("no_proxy", "*")
		s := newScenario(t)
		s.givenRules()
		s.whenRun("curl", "-si", "http://example.com/")
		s.thenStdoutContains("403")
	})
}

func Test_RestrictingNetwork_AllowSpecificHTTPSEndpoints(t *testing.T) {
	// An HTTPS endpoint matching a net:http rule is accessible through the CONNECT proxy.
	// Requests to non-matching endpoints are denied with 403.
	failIfNoCurl(t)

	h, p := testHTTPSServer(t, "HTTPS_ALLOWED")
	srv := testServer{host: h, port: p}

	for _, tt := range []struct {
		name       string
		args       []string
		wantStdout string
	}{
		{"allowed", []string{"curl", "-sk", fmt.Sprintf("https://%s/", srv.hostPort())}, "HTTPS_ALLOWED"},
		{"different_host_denied", []string{"curl", "-si", "--max-time", "5", "https://192.0.2.1:443/"}, "403"},
		{"wrong_port_denied", []string{"curl", "-si", "--max-time", "5", "https://" + net.JoinHostPort(srv.host, "9999") + "/"}, "403"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := newScenario(t)
			s.givenRules("net:http:" + srv.addr())
			s.whenRun(tt.args...)
			s.thenStdoutContains(tt.wantStdout)
		})
	}
}

func Test_RestrictingNetwork_AllowSpecificHTTPEndpoints(t *testing.T) {
	// A plain HTTP endpoint matching a net:http rule is accessible through the proxy.
	// Requests to non-matching endpoints are denied with 403.
	failIfNoCurl(t)

	h, p := testHTTPServer(t, "HTTP_ALLOWED")
	srv := testServer{host: h, port: p}

	for _, tt := range []struct {
		name       string
		args       []string
		wantStdout string
	}{
		{"allowed", []string{"curl", "-s", fmt.Sprintf("http://%s/", srv.hostPort())}, "HTTP_ALLOWED"},
		{"different_host_denied", []string{"curl", "-si", "http://192.0.2.1/"}, "403"},
		{"wrong_port_denied", []string{"curl", "-si", "http://" + net.JoinHostPort(srv.host, "9999") + "/"}, "403"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := newScenario(t)
			s.givenRules("net:http:" + srv.addr())
			s.whenRun(tt.args...)
			s.thenStdoutContains(tt.wantStdout)
		})
	}
}

func Test_RestrictingNetwork_BlockSpecificDomainWithinWildcardAllow_Wildcard(t *testing.T) {
	// A wildcard allow for 127.0.0.0/8 should still let harmless hosts succeed despite the specific deny.
	allowedServer, _, rules := newBlockSpecificDomainScenario(t)

	s := newScenario(t)
	s.givenCurl()
	s.givenRules(rules...)
	s.whenRun("curl", "-s", "--max-time", "5", "http://"+net.JoinHostPort(allowedServer.host, allowedServer.port)+"/")
	s.thenExitCode(0)
	s.thenStdoutContains("ALLOWED_ENDPOINT")
}

func Test_RestrictingNetwork_BlockSpecificDomainWithinWildcardAllow_Deny(t *testing.T) {
	// The specific net:none entry must block the targeted host despite the broader wildcard allow.
	_, blockedServer, rules := newBlockSpecificDomainScenario(t)

	s := newScenario(t)
	s.givenCurl()
	s.givenRules(rules...)
	s.whenRun("curl", "-sf", "--max-time", "5", "http://"+net.JoinHostPort(blockedServer.host, blockedServer.port)+"/")
	s.thenExitCodeNonZero()
}

func newBlockSpecificDomainScenario(t *testing.T) (testServer, testServer, []string) {
	t.Helper()
	allowedHost, allowedPort := testHTTPServer(t, "ALLOWED_ENDPOINT")
	blockedHost, blockedPort := testHTTPServer(t, "should not see this")
	allowedServer := testServer{host: allowedHost, port: allowedPort}
	blockedServer := testServer{host: blockedHost, port: blockedPort}
	rules := []string{
		"net:http:127.0.0.0/8:*",
		fmt.Sprintf("net:none:%s/32:%s", blockedServer.host, blockedServer.port),
	}

	return allowedServer, blockedServer, rules
}

func Test_RestrictingNetwork_BlockSpecificIPWithinCIDRAllow(t *testing.T) {
	// A specific IP deny within an allowed CIDR is blocked, while other IPs in the CIDR are allowed.
	allowedHost, allowedPort := testHTTPServerOnHost(t, "127.0.0.2", "ALLOWED_CIDR_OK")
	deniedHost, deniedPort := testHTTPServerOnHost(t, "127.0.0.99", "should not see this")

	rules := []string{
		"net:http:127.0.0.0/24:*",
		fmt.Sprintf("net:none:%s/32:*", deniedHost),
	}

	for _, tt := range []struct {
		name       string
		args       []string
		wantStdout string
	}{
		{
			name:       "allow_cidr",
			args:       []string{"curl", "-s", fmt.Sprintf("http://%s/", net.JoinHostPort(allowedHost, allowedPort))},
			wantStdout: "ALLOWED_CIDR_OK",
		},
		{
			name: "deny_specific_ip",
			args: []string{
				"curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}",
				fmt.Sprintf("http://%s/", net.JoinHostPort(deniedHost, deniedPort)),
			},
			wantStdout: "403",
		},
		{
			name:       "outside_cidr_default_deny",
			args:       []string{"curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}", "http://192.0.2.1:8080/"},
			wantStdout: "403",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := newScenario(t)
			s.givenCurl()
			s.givenRules(rules...)
			s.whenRun(tt.args...)
			s.thenExitCode(0)
			s.thenStdoutContains(tt.wantStdout)
		})
	}
}

func Test_RestrictingNetwork_DirectTCPConnectionsFail(t *testing.T) {
	// Direct TCP connections must fail even when net rules exist because the sandbox has no NIC.
	for _, tt := range []struct {
		name string
		code string
	}{
		{
			name: "matching_endpoint_direct_tcp",
			code: "import socket; s=socket.socket(); s.settimeout(2); s.connect(('192.0.2.1', 443))",
		},
		{
			name: "non_matching_endpoint_direct_tcp",
			code: "import socket; s=socket.socket(); s.settimeout(2); s.connect(('1.1.1.1', 80))",
		},
		{
			name: "hostname_requires_dns",
			code: "import socket; s=socket.socket(); s.settimeout(2); s.connect(('example.com', 443))",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := newScenario(t)
			s.givenPython3()
			s.givenRules("net:http:192.0.2.1:443")
			s.whenRun("python3", "-c", tt.code)
			s.thenExitCodeNonZero()
		})
	}
}

func Test_RestrictingNetwork_UDPTrafficBlocked(t *testing.T) {
	// UDP is blocked even when a matching http rule exists for the target — the proxy only handles
	// HTTP/HTTPS, so UDP bypasses it and fails because the sandbox has no NIC.
	s := newScenario(t)
	s.givenPython3()

	s.givenRules("net:http:1.1.1.1:53")

	s.whenRun("python3", "-c",
		"import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(2); s.sendto(b'test', ('1.1.1.1', 53))")

	s.thenExitCodeNonZero()
}

func Test_RestrictingNetwork_ExitCodePreserved(t *testing.T) {
	// Exit codes are faithfully forwarded regardless of value.
	for _, tt := range []struct {
		name string
		code int
	}{
		{"success", 0},
		{"one", 1},
		{"arbitrary", 42},
		{"command_not_found_sentinel", 127},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := newScenario(t)
			s.givenRules()
			s.whenRun("sh", "-c", fmt.Sprintf("exit %d", tt.code))
			s.thenExitCode(tt.code)
		})
	}
}

func Test_RestrictingNetwork_WildcardPortAccess(t *testing.T) {
	// A wildcard port rule allows access to the host on any port; the host constraint is still enforced.
	h1, p1 := testHTTPServer(t, "WILDCARD_PORT_OK")
	srv1 := testServer{host: h1, port: p1}
	h2, p2 := testHTTPServer(t, "WILDCARD_PORT_OK2")
	srv2 := testServer{host: h2, port: p2}

	for _, tt := range []struct {
		name       string
		args       []string
		wantStdout string
	}{
		{
			name:       "allowed_port1",
			args:       []string{"curl", "-s", fmt.Sprintf("http://%s/", srv1.hostPort())},
			wantStdout: "WILDCARD_PORT_OK",
		},
		{
			name:       "allowed_port2",
			args:       []string{"curl", "-s", fmt.Sprintf("http://%s/", srv2.hostPort())},
			wantStdout: "WILDCARD_PORT_OK2",
		},
		{
			name:       "different_host_denied",
			args:       []string{"curl", "-si", "http://192.0.2.1:80/"},
			wantStdout: "403",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := newScenario(t)
			s.givenCurl()
			s.givenRules(fmt.Sprintf("net:http:%s:*", srv1.host))
			s.whenRun(tt.args...)
			s.thenStdoutContains(tt.wantStdout)
		})
	}
}
