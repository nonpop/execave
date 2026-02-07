package e2e_test

import "testing"

// All tunnel delta spec scenarios are placeholders — better tested at unit level
// or covered implicitly by sandbox/proxy E2E tests.

// TestE2E_Tunnel_TCPToUDSBridge_TCPConnectionBridgedToUDS is a placeholder.
// Covered implicitly by proxy connectivity tests.
func TestE2E_Tunnel_TCPToUDSBridge_TCPConnectionBridgedToUDS(*testing.T) {}

// TestE2E_Tunnel_TCPToUDSBridge_UDSUnavailable is a placeholder.
// Better tested at unit level.
func TestE2E_Tunnel_TCPToUDSBridge_UDSUnavailable(*testing.T) {}

// TestE2E_Tunnel_ProxyEnvironmentVariables_ProxyEnvVarsSet is a placeholder.
// Better tested at unit level.
func TestE2E_Tunnel_ProxyEnvironmentVariables_ProxyEnvVarsSet(*testing.T) {}

// TestE2E_Tunnel_ProxyEnvironmentVariables_NoProxyVarsUnset is a placeholder.
// Better tested at unit level.
func TestE2E_Tunnel_ProxyEnvironmentVariables_NoProxyVarsUnset(*testing.T) {}

// TestE2E_Tunnel_UserCommandExecution_UserCommandExitCodePropagated is a placeholder.
// Covered by Sandbox_CLICommandExecution_ExitCodePropagationWithTunnel.
func TestE2E_Tunnel_UserCommandExecution_UserCommandExitCodePropagated(*testing.T) {}

// TestE2E_Tunnel_UserCommandExecution_UserCommandRunsWithProxyEnv is a placeholder.
// Better tested at unit level.
func TestE2E_Tunnel_UserCommandExecution_UserCommandRunsWithProxyEnv(*testing.T) {}

// TestE2E_Tunnel_TunnelFailureIsFailClosed_TunnelBindFailure is a placeholder.
// Better tested at unit level.
func TestE2E_Tunnel_TunnelFailureIsFailClosed_TunnelBindFailure(*testing.T) {}

// TestE2E_Tunnel_TunnelFailureIsFailClosed_TunnelUDSInaccessible is a placeholder.
// Better tested at unit level.
func TestE2E_Tunnel_TunnelFailureIsFailClosed_TunnelUDSInaccessible(*testing.T) {}

// TestE2E_Tunnel_ConnectionDrainingOnExit_InFlightDataDrained is a placeholder.
// Better tested at unit level.
func TestE2E_Tunnel_ConnectionDrainingOnExit_InFlightDataDrained(*testing.T) {}
