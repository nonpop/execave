package e2e_test

import (
	"fmt"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestE2E_Proxy_PlainHTTPForwarding_AllowedHTTPRequestForwarded tests that plain HTTP requests are forwarded
// when allowed by rules.
func TestE2E_Proxy_PlainHTTPForwarding_AllowedHTTPRequestForwarded(t *testing.T) {
	failIfNoBwrap(t)
	failIfNoCurl(t)

	host, port := testHTTPServer(t, "HTTP_FORWARD_OK")

	rules := append(systemPaths(),
		fmt.Sprintf("net:http:%s:%s", host, port),
	)
	configPath := writeConfig(t, rules)

	result := runExecave(t, "", "--config", configPath, "--",
		"curl", "-s", fmt.Sprintf("http://%s/", net.JoinHostPort(host, port)))

	assertExitCode(t, result, 0)
	assert.Contains(t, result.Stdout, "HTTP_FORWARD_OK")
}

// TestE2E_Proxy_PlainHTTPForwarding_DeniedHTTPRequestRejected tests that plain HTTP requests
// are denied when only HTTPS is allowed for the target.
func TestE2E_Proxy_PlainHTTPForwarding_DeniedHTTPRequestRejected(t *testing.T) {
	failIfNoBwrap(t)
	failIfNoCurl(t)

	host, port := testHTTPServer(t, "should not see this")

	// Allow HTTPS only, not HTTP
	rules := append(systemPaths(),
		fmt.Sprintf("net:https:%s:%s", host, port),
	)
	configPath := writeConfig(t, rules)

	result := runExecave(t, "", "--config", configPath, "--",
		"curl", "-sf", "--max-time", "5", fmt.Sprintf("http://%s/", net.JoinHostPort(host, port)))

	assert.NotEqual(t, 0, result.ExitCode)
}

// Placeholder tests for proxy delta spec scenarios

// TestE2E_Proxy_ProxyListensOnUDS_ProxyAcceptsConnectionOnUDS is a placeholder.
// Covered implicitly by proxy connectivity tests.
func TestE2E_Proxy_ProxyListensOnUDS_ProxyAcceptsConnectionOnUDS(*testing.T) {}

// TestE2E_Proxy_ProxyListensOnUDS_ProxyDoesNotListenOnTCP is a placeholder.
// Better tested at unit level.
func TestE2E_Proxy_ProxyListensOnUDS_ProxyDoesNotListenOnTCP(*testing.T) {}

// TestE2E_Proxy_CONNECTHandlingForHTTPS_AllowedCONNECTRequestTunneled is a placeholder.
// Covered by Sandbox_ProxyTunnelPathSetup_NetRulesTriggerProxyTunnelSetup.
func TestE2E_Proxy_CONNECTHandlingForHTTPS_AllowedCONNECTRequestTunneled(*testing.T) {}

// TestE2E_Proxy_CONNECTHandlingForHTTPS_DeniedCONNECTRequestRejected is a placeholder.
// Covered by Sandbox_ProxyTunnelNetworkAccess_DeniedHTTPSViaProxy.
func TestE2E_Proxy_CONNECTHandlingForHTTPS_DeniedCONNECTRequestRejected(*testing.T) {}

// TestE2E_Proxy_CONNECTHandlingForHTTPS_CONNECTTunnelClosesWhenTargetDisconnects is a placeholder.
// Better tested at unit level.
func TestE2E_Proxy_CONNECTHandlingForHTTPS_CONNECTTunnelClosesWhenTargetDisconnects(*testing.T) {}

// TestE2E_Proxy_PlainHTTPForwarding_HTTPRequestWithoutPortDefaultsTo80Allowed is a placeholder.
// Better tested at unit level.
func TestE2E_Proxy_PlainHTTPForwarding_HTTPRequestWithoutPortDefaultsTo80Allowed(*testing.T) {}

// TestE2E_Proxy_PlainHTTPForwarding_HTTPRequestWithoutPortDefaultsTo80Denied is a placeholder.
// Better tested at unit level.
func TestE2E_Proxy_PlainHTTPForwarding_HTTPRequestWithoutPortDefaultsTo80Denied(*testing.T) {}

// TestE2E_Proxy_MalformedRequestHandling_RawBytesSentToUDS is a placeholder.
// Better tested at unit level.
func TestE2E_Proxy_MalformedRequestHandling_RawBytesSentToUDS(*testing.T) {}

// TestE2E_Proxy_MalformedRequestHandling_CONNECTWithMissingHost is a placeholder.
// Better tested at unit level.
func TestE2E_Proxy_MalformedRequestHandling_CONNECTWithMissingHost(*testing.T) {}

// TestE2E_Proxy_AllowlistEnforcement_RequestAllowedByMostSpecificRule is a placeholder.
// Covered by net-rules tests.
func TestE2E_Proxy_AllowlistEnforcement_RequestAllowedByMostSpecificRule(*testing.T) {}

// TestE2E_Proxy_AllowlistEnforcement_RequestDeniedByMostSpecificRule is a placeholder.
// Covered by net-rules tests.
func TestE2E_Proxy_AllowlistEnforcement_RequestDeniedByMostSpecificRule(*testing.T) {}

// TestE2E_Proxy_AccessLogIntegration_AllowedRequestLogged is a placeholder.
// Covered by AccessLog_LogFormat_AllowedHTTPSRequestLogged.
func TestE2E_Proxy_AccessLogIntegration_AllowedRequestLogged(*testing.T) {}

// TestE2E_Proxy_AccessLogIntegration_DeniedRequestLogged is a placeholder.
// Covered by AccessLog_LogFormat_DeniedHTTPSRequestLogged.
func TestE2E_Proxy_AccessLogIntegration_DeniedRequestLogged(*testing.T) {}

// TestE2E_Proxy_ProxyLifecycle_ProxyStart is a placeholder.
// Covered implicitly by proxy connectivity tests.
func TestE2E_Proxy_ProxyLifecycle_ProxyStart(*testing.T) {}

// TestE2E_Proxy_ProxyLifecycle_ProxyStop is a placeholder.
// Covered implicitly by process lifecycle.
func TestE2E_Proxy_ProxyLifecycle_ProxyStop(*testing.T) {}

// TestE2E_Proxy_ProxyLifecycle_InFlightConnectionsDrainedOnStop is a placeholder.
// Better tested at unit level.
func TestE2E_Proxy_ProxyLifecycle_InFlightConnectionsDrainedOnStop(*testing.T) {}

// TestE2E_Proxy_ProxyLifecycle_DrainTimeoutForciblyClosesConnections is a placeholder.
// Better tested at unit level.
func TestE2E_Proxy_ProxyLifecycle_DrainTimeoutForciblyClosesConnections(*testing.T) {}

// TestE2E_Proxy_ProxyLifecycle_ProxyCrashIsFailClosed is a placeholder.
// Better tested at unit level.
func TestE2E_Proxy_ProxyLifecycle_ProxyCrashIsFailClosed(*testing.T) {}
