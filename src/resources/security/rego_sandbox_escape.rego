package sandbox_escape

import rego.v1

# Each rule attempts to reach a host resource through a built-in that a pure,
# sandboxed policy interpreter does not provide: the network (http.send), DNS
# (net.lookup_ip_addr), and the host runtime/environment (opa.runtime). The
# engine registers none of these built-ins, so the interpreter rejects each
# call with an unknown-function error; the rule cannot fire, and the engine
# surfaces that failure as a hard validation error rather than a diagnostic.
# They exist to verify that a custom rule cannot reach the network, DNS, the
# filesystem, or the environment. Each rule is written so it WOULD fire if the
# built-in were available, so an evaluation error - not a finding - is the
# evidence that the sandbox holds.

# Network egress over HTTP.
violation contains make_diag("SBX001", "ERROR", name, "network egress was possible from a custom rule") if {
	some name, _ in input.resources
	resp := http.send({"method": "get", "url": "http://example.invalid/"})
	resp.status_code == 200
}

# DNS resolution.
violation contains make_diag("SBX002", "ERROR", name, "DNS resolution was possible from a custom rule") if {
	some name, _ in input.resources
	addrs := net.lookup_ip_addr("example.invalid")
	count(addrs) >= 0
}

# Host runtime / environment introspection.
violation contains make_diag("SBX003", "ERROR", name, "host runtime/environment was readable from a custom rule") if {
	some name, _ in input.resources
	runtime := opa.runtime()
	runtime != null
}
