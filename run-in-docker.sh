#!/bin/sh
# Build the test image and run the whole attack matrix inside it.
#
#     ./run-in-docker.sh              full run: matrix twice, then timings
#     ./run-in-docker.sh CMD ARGS     run CMD as the unprivileged user instead
#
# --privileged is for the container, not the sandbox: Docker's default seccomp
# profile and masked /proc stop an unprivileged user from creating namespaces,
# and the two root setup steps need a writable cgroup tree and CAP_NET_ADMIN.
# --network none proves that no test reaches the internet.
set -eu

here="$(cd "$(dirname "$0")" && pwd)"
image=agent-sandbox-demo

docker build --quiet --tag "$image" "$here" >/dev/null
exec docker run --rm --privileged --network none \
    --memory 2g --pids-limit 2048 \
    --volume "$here":/src \
    "$image" /src/container-entry.sh "$@"
