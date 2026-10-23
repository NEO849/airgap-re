# airgap-re — container image for the Glama MCP directory (and any stdio-MCP host).
#
# Why this file exists: without it, Glama guesses the start command from the repo
# name ("sandboxed-re-mcp"), but the console script is "airgap-re" -> the guessed
# command does not exist -> the container exits before responding. This Dockerfile
# makes the build deterministic and pins the correct stdio start command.
FROM python:3.12-slim

# Ship only bubblewrap (the server's signature isolation tool; reliably in Debian main).
# The heavier RE backends (Ghidra/radare2/rizin/capa/floss/jadx) are intentionally NOT
# bundled: they are large and not needed for MCP tool DISCOVERY — the server starts and
# lists every tool without them; a tool invoked without its backend returns a clean
# "not available" error. A full-capability deployment installs those on the host (README).
# (bubblewrap also needs a privileged runtime for real isolation, which Glama's inspector
# does not grant — fine, discovery only needs the server to start and answer the ping.)
RUN apt-get update \
 && apt-get install -y --no-install-recommends bubblewrap \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir .

# stdio is the MCP channel -> logs must never hit stdout, and the log path must be
# writable regardless of the working directory's permissions.
ENV REMCP_LOG=/tmp/re-mcp.log \
    PYTHONUNBUFFERED=1

# Explicit, correct stdio start command (no name guessing).
CMD ["python", "-m", "re_mcp.server"]
