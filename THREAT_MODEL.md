# Threat Model

## Asset to protect
The analyst's host and credentials while inspecting a potentially **hostile** binary.

## Adversary
A crafted input sample that aims to exploit a parser/analysis bug (in Ghidra, capa, floss, r2,
angr, or an unpacker) to achieve code execution, then to (a) exfiltrate data, (b) tamper with
the host, or (c) exhaust resources.

## Trust boundaries
```
 analyst / MCP client   ─ trusted
 ─────────────────────────────────────────────
 re_mcp server (Python) ─ trusted, auditable (~1.2k LoC)
 ─────────────────────────────────────────────  ← bubblewrap boundary (untrusted side below)
 analysis backends + the SAMPLE ─ untrusted when sample is third-party
```

## Mitigations (mapped to adversary goals)

| Adversary goal | Mitigation | Enforced by |
|---|---|---|
| Phone home / exfiltrate | `bwrap --unshare-all` removes the net namespace — no egress possible | `test_shipped_script_blocks_egress` |
| Tamper with host files | host paths read-only, except a throwaway `/out` removed on exit | `test_shipped_script_host_readonly` |
| Exhaust memory/CPU/PIDs | cgroup `MemoryMax`/`TasksMax`/`CPUQuota` via systemd-run | `test_cgroup_memory_cap_enforced` |
| Gain privileges | bwrap drops all capabilities; `--new-session`; non-root | design + bwrap defaults |
| Execute the payload | purely static pipeline; sample mounted read-only, never run | design (`sandbox_analyze.sh`) |

## Residual risk (honest)
- No seccomp filter → a kernel-level namespace/cgroup escape is out of scope of these mitigations.
- The non-sandboxed `analyze_binary` path trades isolation for speed and is for trusted inputs only.
- Backends themselves are trusted to be the code we run; supply-chain integrity of those tools is
  the operator's responsibility.
