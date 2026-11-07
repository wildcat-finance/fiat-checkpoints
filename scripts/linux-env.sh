#!/bin/sh
# Run a command in the pinned x86_64 Linux test environment.
#
#   scripts/linux-env.sh start          create or start the colima profile
#   scripts/linux-env.sh build          build the pinned test image (needs SKILLS_REPO)
#   scripts/linux-env.sh facts          print kernel, architecture and image id
#   scripts/linux-env.sh db-start       start the pinned PostgreSQL 16 test server
#   scripts/linux-env.sh db-stop        remove that server and its socket volume
#   scripts/linux-env.sh run CMD...     run CMD in the image at this checkout
#
# The profile mounts this checkout writable and the Git directory read-only at
# their host paths. The container has no network and runs as the calling user.
# It mounts the test server's socket volume, the only way it reaches PostgreSQL.
#
# FIAT_LINUX_PROFILE=latency selects the native aarch64 latency profile instead:
# colima profile fiat-s862a-arm under vz with no emulation, and the latency
# image from containers/latency.Dockerfile. Only scripts/latency.py runs there;
# every other check stays on the x86_64 profile.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
GIT_COMMON=$(git -C "$ROOT" rev-parse --path-format=absolute --git-common-dir)
POSTGRES_VOLUME=fiat-checkpoints-postgres-socket

refuse() {
  printf 'linux-env-refused: %s\n' "$1" >&2
  exit 2
}

case "${FIAT_LINUX_PROFILE:-}" in
  '')
    PROFILE=fiat-s862a ARCH=x86_64 VM_TYPE=qemu MOUNT_TYPE=sshfs PLATFORM=linux/amd64
    IMAGE=fiat-checkpoints-test:local DOCKERFILE=containers/test.Dockerfile
    ;;
  latency)
    PROFILE=fiat-s862a-arm ARCH=aarch64 VM_TYPE=vz MOUNT_TYPE=virtiofs PLATFORM=linux/arm64
    IMAGE=fiat-checkpoints-latency:local DOCKERFILE=containers/latency.Dockerfile
    ;;
  *)
    refuse profile-unknown
    ;;
esac
CONTEXT=colima-$PROFILE

docker_env() {
  docker --context "$CONTEXT" "$@"
}

case "${1:-}" in
  start)
    if colima status --profile "$PROFILE" >/dev/null 2>&1; then
      exit 0
    fi
    exec colima start --profile "$PROFILE" --arch "$ARCH" --vm-type "$VM_TYPE" \
      --cpus 4 --memory 8 --disk 40 --runtime docker --mount-type "$MOUNT_TYPE" \
      --mount "$ROOT:w" --mount "$GIT_COMMON"
    ;;
  build)
    # The protocol trees come from a local Skills clone at the locked commits.
    [ -n "${SKILLS_REPO:-}" ] || refuse skills-repo-missing
    rm -rf "$ROOT/.protocol-trees"
    python3 "$ROOT/scripts/protocol_trees.py" export --skills-repo "$SKILLS_REPO" \
      --out "$ROOT/.protocol-trees"
    exec docker --context "$CONTEXT" build --platform "$PLATFORM" -f "$ROOT/$DOCKERFILE" \
      -t "$IMAGE" "$ROOT"
    ;;
  facts)
    docker_env run --rm --platform "$PLATFORM" --network none "$IMAGE" \
      python3 -c 'import os, platform; u = os.uname(); print("kernel=" + u.release); print("machine=" + u.machine); print("python=" + platform.python_version())'
    printf 'image=%s\n' "$(docker_env image inspect --format '{{.Id}}' "$IMAGE")"
    ;;
  db-start|db-stop)
    DOCKER_CONTEXT=$CONTEXT FIAT_TEST_PLATFORM=$PLATFORM exec "$ROOT/scripts/test-postgres.sh" "${1#db-}"
    ;;
  run)
    shift
    [ "$#" -gt 0 ] || refuse command-missing
    exec docker --context "$CONTEXT" run --rm --platform "$PLATFORM" --network none \
      --user "$(id -u):$(id -g)" --env HOME=/tmp \
      --env FIAT_TEST_POSTGRES=/run/fiat-postgres --volume "$POSTGRES_VOLUME:/run/fiat-postgres" \
      --volume "$ROOT:$ROOT" --volume "$GIT_COMMON:$GIT_COMMON:ro" \
      --workdir "$ROOT" "$IMAGE" "$@"
    ;;
  *)
    refuse usage
    ;;
esac
