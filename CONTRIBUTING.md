# Contributing

Thanks for looking. This project values a small, auditable surface over feature count — please
keep that in mind for PRs.

## Dev setup
```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
sudo apt-get install -y bubblewrap radare2   # analysis + isolation backends
```

## The gate (must be green before merge)
```bash
ruff check re_mcp benchmark tests     # lint (select = E,F,I,W)
mypy re_mcp                           # types
pytest -v                             # tests incl. the isolation proof
python benchmark/run_benchmark.py     # reproducible metrics
```
CI runs exactly this on Ubuntu with bubblewrap installed.

## Ground rules
- **Read-only at the target.** No tool may patch, rebuild, or execute a sample.
- **Every security claim needs a test.** If you harden the sandbox, add/extend a proof in
  `tests/test_sandbox_isolation.py`.
- **No hardcoded host paths.** Everything resolvable goes through `re_mcp/config.py`
  (env override → auto-discovery → documented default).
- **Keep the footprint small.** New runtime dependencies need a strong justification.
