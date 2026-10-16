# Architecture

`airgap-re` is a thin MCP bridge. The server holds no RE logic; it validates input,
selects the trusted vs. sandboxed path, and shells out to a pre-existing backend stack.

## Data flow & trust boundary

```mermaid
flowchart TD
    A[MCP client / AI agent] -->|tool call + path| B[re_mcp.server]
    B --> V{_validate<br/>abs path, is-file, size cap}
    V -->|invalid| E[JSON error]
    V -->|valid| P{trusted or untrusted?}

    P -->|own / in-scope| H[analyze_binary<br/>host-side triage]
    P -->|untrusted| S[sandbox_analyze_binary]

    subgraph chamber[bubblewrap chamber: --unshare-all, caps dropped, host read-only, cgroup caps]
        S --> T[re_triage.py]
        T --> G[Ghidra headless]
        T --> C[capa / floss]
        T --> N[angr optional]
    end

    H --> T2[re_triage.py host-side]
    B --> R[list_symbols: r2 / rizin]
    B --> D[decompile_function: Ghidra]
    B --> K[analyze_apk: native .so, sandboxed]

    T --> O[(ranked JSON<br/>via /out, host-temp)]
    chamber -.no network, no host write.-> X((egress impossible))
```

## Key properties
- **Config-driven, relocatable.** No hardcoded host paths; see `re_mcp/config.py`.
- **One pinned runtime dependency** (`mcp`). Backends are external, bring-your-own.
- **The sandbox boundary is the product.** Everything below `bubblewrap` is treated as hostile
  when the sample is third-party; see `THREAT_MODEL.md`.
