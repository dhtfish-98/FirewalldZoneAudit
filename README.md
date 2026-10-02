# FirewalldZoneAudit

Zone XML and service exposure snapshot audit. Complete independent **new scope**, not the whole upstream system rewritten.

Input: `{"zones":{"public":"<zone target=\"DROP\"><interface name=\"eth0\"/></zone>"},"services":{},"active_zones":["public"]}`. All supplied zones and referenced service definitions are inspected. XML DTD/entities, malformed roots, hidden leaf children and deep/huge trees are rejected. Checks cover explicit restrictive default targets, declared active zone coverage, interface/source bindings, service references, valid port bounds/protocols, duplicates, broad ranges and exposure declarations. Rich rules, forwarding/NAT, ipsets/MAC scope, module/protocol/helper services, implicit targets and uncertain reachability are OPEN. A closed DROP zone bound to an interface can PASS this static scope; a service opening remains OPEN for source/topology review. Supplied names do not prove live active zones or runtime isolation.

## Use and output

Install `artifacts/*.whl` and run `firewalld-zone-audit examples/good.json`, or `python -m firewalld_zone_audit examples/good.json`. JSON findings have PASS/FAIL/OPEN, evidence, explanation and counts. Exit codes: PASS 0, FAIL 1, ERROR 2, OPEN 3. Incomplete/unsupported evidence cannot produce exit 0. Input: regular non-symlink unchanged file, 2 MiB maximum, 32 JSON layers, 100000 nodes, no duplicate keys/nonfinite values; findings cap 20000. Each project is independently packaged with no external runtime dependency.

## Verification and limits

Read `ORIGIN.md`, `NOTICE` where present, `tests/`, `examples/expectations.json`, `VALIDATION.md` and exact `artifacts/validation.json`. Tests use public frozen policy data or synthetic fixtures only. Local parser/policy/wheel/CLI results are separate from real Linux/Windows execution, effective security, upstream equivalence and CVP eligibility/approval, which remain OPEN. No live host collection, code execution, configuration change or network action occurs.
