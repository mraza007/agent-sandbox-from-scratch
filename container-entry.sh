#!/bin/sh
# Runs inside the test container. Root does the two setup steps, then
# everything else runs as the unprivileged user "agent".
set -eu

PYTHON="${PYTHON:-python3}"

# Run from the container's own disk, not the bind mount, so timings do not
# measure the Mac file share.
mkdir -p /opt/agent-sandbox /out
cp /src/*.py /opt/agent-sandbox/
"$PYTHON" -m compileall -q /opt/agent-sandbox
chown agent:agent /out

"$PYTHON" /opt/agent-sandbox/lab.py setup agent
"$PYTHON" /opt/agent-sandbox/cgroup_setup.py agent $$

status=0
if [ $# -eq 0 ]; then
    set -- "$PYTHON" /opt/agent-sandbox/run_matrix.py --out /out
fi
setpriv --reuid=agent --regid=agent --init-groups \
    env HOME=/home/agent USER=agent "$@" || status=$?

cp /out/* /src/ 2>/dev/null || true
exit $status
