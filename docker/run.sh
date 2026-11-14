#!/usr/bin/env bash
# Run the red-team suite with real OS-level isolation.
#
#   ./docker/run.sh --scripted
#   ./docker/run.sh --model qwen2.5:3b      (needs a reachable Ollama; add --network=host)
#
# --network=none is the part that actually enforces "no exfiltration": the policy
# can only *ask* about curl, this removes the socket.
set -euo pipefail
cd "$(dirname "$0")/.."

docker build -t agentguard:local -f docker/Dockerfile .

exec docker run --rm -it \
  --network=none \
  --read-only \
  --tmpfs /tmp:rw,size=256m \
  agentguard:local "$@"
