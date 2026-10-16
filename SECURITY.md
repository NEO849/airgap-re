# Security Policy

## Lawful-use scope
`sandboxed-re-mcp` is for reverse engineering you are authorized to perform: software you own,
in-scope bug-bounty targets, CTFs, abandonware, and interoperability research permitted by
applicable law. It is **read-only**: it never patches, rebuilds, or executes the target.

## Design stance
- The target is treated as **data**, mounted read-only, and analysed statically. It is never run.
- Untrusted samples are analysed inside a bubblewrap chamber with **no network namespace**
  (`--unshare-all`), capabilities dropped, host bound read-only (except one throwaway `/out`
  removed on exit), and cgroup resource caps.
- These guarantees are enforced by tests that drive the **shipped** `engine/sandbox_analyze.sh`
  (`tests/test_sandbox_isolation.py`); removing `--unshare-all` turns the egress test red, so a
  regression fails CI.

## Known limitations (stated honestly)
- No custom seccomp-BPF filter is applied (see README "Non-goal"). Isolation rests on
  namespaces + cap-drop + read-only binds + cgroup, not on syscall filtering.
- `analyze_binary` (the non-sandboxed path) is intended for your **own / in-scope** files.
  For anything untrusted, use `sandbox_analyze_binary` / `analyze_apk` (sandboxed by default).
- Backends (Ghidra, capa, floss, angr) are third-party; a parser bug in them is the reason the
  sandbox exists, but no sandbox is a guarantee against every conceivable escape.

## Reporting a vulnerability
Open a private security advisory on the repository, or contact the maintainer listed there.
Please do not file public issues for security reports.
