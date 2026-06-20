# Charon authorization policy (Phase 4).
#
# Mirrors charon.policy.EmbeddedPolicyEngine so the gateway behaves identically
# whether it runs the embedded engine or OPA.
#
# Decision endpoint used by OpaPolicyEngine:
#   POST /v1/data/charon/authz   ->  { "result": { "allow": bool, "reason": str } }
#
# Validate with:  opa check policies/authz.rego
# Run OPA with:   opa run --server policies/
package charon.authz

import rego.v1

default allow := false

# Allow only when the scope check and every applicable constraint pass.
allow if {
	scope_ok
	path_ok
	amount_ok
}

# --- 1. scope check --------------------------------------------------------
scope_ok if input.required_scope == ""
scope_ok if input.required_scope in input.scopes

# --- 2. path confinement (filesystem tools) --------------------------------
# Pass when no root is configured, or the path stays within the root and
# contains no parent-directory traversal.
path_ok if not input.constraints.allowed_root

path_ok if {
	root := input.constraints.allowed_root
	p := object.get(input.args, "path", "")
	not contains(p, "..")
	startswith(p, root)
}

# --- 3. amount cap (payment tools) -----------------------------------------
amount_ok if not input.constraints.max_amount

amount_ok if {
	input.constraints.max_amount
	not input.args.amount
}

amount_ok if {
	max := input.constraints.max_amount
	amt := input.args.amount
	amt <= max
}

# --- human-readable reason -------------------------------------------------
reason := "permitted by policy" if allow

reason := sprintf("missing required scope %q (have %v)", [input.required_scope, input.scopes]) if {
	not allow
	not scope_ok
}

reason := sprintf("path %q escapes allowed root %q", [object.get(input.args, "path", ""), input.constraints.allowed_root]) if {
	not allow
	scope_ok
	not path_ok
}

reason := sprintf("amount %v exceeds max %v", [input.args.amount, input.constraints.max_amount]) if {
	not allow
	scope_ok
	path_ok
	not amount_ok
}
