> 目录已整理：文档在「项目文档」，构建、缓存与暂存输入在「Build」。从仓库根目录运行 `python3 构建.py --build`；如需使用本文原有源码命令，先运行 `python3 构建.py --stage --ci`，再进入 `Build/源码`。暂存会恢复原输入路径。现有版本和历史验证记录按各自提交理解。

# FirewalldZoneAudit

Version **0.1.2**.

New implementation author: **dhtfish98**. Copyright (c) 2026 dhtfish98 applies to the new implementation code. Upstream policy data, original notices and source references retain their original attribution.

Zone XML and service exposure snapshot audit. Complete independent **new scope**, not the whole upstream system rewritten.

Input: `{"zones":{"public":"<zone target=\"DROP\"><interface name=\"eth0\"/></zone>"},"services":{},"active_zones":["public"]}`. All supplied zones and referenced service definitions are inspected. XML DTD/entities, malformed roots, hidden leaf children and deep/huge trees are rejected. Checks cover explicit restrictive default targets, declared active zone coverage, interface/source bindings, service references, valid port bounds/protocols, duplicates, broad ranges and exposure declarations. Rich rules, forwarding/NAT, ipsets/MAC scope, module/protocol/helper services, implicit targets and uncertain reachability are OPEN. A closed DROP zone bound to an interface can PASS this static scope; a service opening remains OPEN for source/topology review. Supplied names do not prove live active zones or runtime isolation.

## Use and output

Install the published v0.1.2 wheel from GitHub Releases, or run `python3 构建.py --build` from the repository root and install the wheel under the reported `Build/新构建/.../发行/` directory; then run `firewalld-zone-audit examples/good.json`, or `python -m firewalld_zone_audit examples/good.json`. JSON findings have PASS/FAIL/OPEN, evidence, explanation and counts. Exit codes: PASS 0, FAIL 1, ERROR 2, OPEN 3. Incomplete/unsupported evidence cannot produce exit 0. Input: regular non-symlink unchanged file, 2 MiB maximum, 32 JSON layers, 100000 nodes, no duplicate keys/nonfinite values; findings cap 20000. Each project is independently packaged with no external runtime dependency.

## Verification and limits

Read `ORIGIN.md`, `NOTICE` where present, `tests/`, `examples/expectations.json`, `VALIDATION.md` and exact `artifacts/validation.json`. Tests use public frozen policy data or synthetic fixtures only. Local parser/policy/wheel/CLI results are separate from real Linux/Windows execution, effective security, upstream equivalence and CVP eligibility/approval, which remain OPEN. No live host collection, code execution, configuration change or network action occurs.


The file CLI requires non-following, non-blocking descriptor support (`O_NOFOLLOW` and `O_NONBLOCK`). Missing capabilities return controlled ERROR without weakening safe-file reads. This profile targets capable macOS/Linux environments; native Windows file-CLI behavior has not been verified. Windows observations remain supplied JSON data.

Short/description are strictly text-only without attributes. Nested children are rejected even when the frozen upstream SAX handler would process them as forwarding or service declarations; this tool never ignores such hidden semantics.
