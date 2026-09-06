#!/usr/bin/env bash
# Start everything: the web dashboard (background) + the MCP server (stdio,
# foreground). Point an MCP client's command at this script instead of
# `vera mcp` and the dashboard comes up alongside the assistant session;
# when the client ends the session, the dashboard is shut down too.
#
#   ./start.sh [--case PATH] [--port N] [--actor NAME] [--no-browser]
#
# Also fine to run by hand in a terminal (Ctrl+C stops both).
#
# stdout belongs to the MCP protocol — everything else must go to stderr.

set -euo pipefail

# find vera: PATH, then the venv next to this script, then the repo itself
script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
if command -v vera >/dev/null 2>&1; then
    vera=(vera)
elif [[ -x "$script_dir/.venv/bin/vera" ]]; then
    vera=("$script_dir/.venv/bin/vera")
else
    vera=(env "PYTHONPATH=$script_dir" python3 -m vera)
fi

case_args=()
actor_args=()
browser_args=()
port=8845

while [[ $# -gt 0 ]]; do
    case "$1" in
        --case)       case_args=(--case "$2"); shift 2 ;;
        --port)       port="$2"; shift 2 ;;
        --actor)      actor_args=(--actor "$2"); shift 2 ;;
        --no-browser) browser_args=(--no-browser); shift ;;
        *) echo "usage: $0 [--case PATH] [--port N] [--actor NAME] [--no-browser]" >&2
           exit 1 ;;
    esac
done

# dashboard — skip if something is already serving on the port (a dashboard
# left running from an earlier session is the normal case, not an error)
if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
    echo "vera dashboard already running: http://127.0.0.1:$port" >&2
else
    "${vera[@]}" "${case_args[@]}" serve --port "$port" "${browser_args[@]}" >&2 &
    serve_pid=$!
    trap 'kill "$serve_pid" 2>/dev/null || true' EXIT
    echo "vera dashboard: http://127.0.0.1:$port (pid $serve_pid)" >&2
fi

# MCP server on stdio, foreground; the EXIT trap stops the dashboard with it
"${vera[@]}" "${case_args[@]}" mcp "${actor_args[@]}"
