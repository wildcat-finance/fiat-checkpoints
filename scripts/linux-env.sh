#!/bin/sh
# Run a command in the pinned x86_64 Linux test environment.
#
#   scripts/linux-env.sh start          create or start the colima profile
#   scripts/linux-env.sh build          build the pinned test image (needs SKILLS_REPO)
#   scripts/linux-env.sh facts          print kernel, architecture and image id
#   scripts/linux-env.sh run CMD...     run CMD in the image at this checkout
#
# The profile mounts this checkout writable and the Git directory read-only at
# their host paths. The container has no network and runs as the calling user.
set -eu

PROFILE=fiat-s862a
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
GIT_COMMON=$(git -C "$ROOT" rev-parse --path-format=absolute --git-common-dir)
CONTEXT=colima-$PROFILE
IMAGE=fiat-checkpoints-test:local

refuse() {
  printf 'linux-env-refused: %s\n' "$1" >&2
  exit 2
}

docker_env() {
  docker --context "$CONTEXT" "$@"
}

case "${1:-}" in
  start)
    if colima status --profile "$PROFILE" >/dev/null 2>&1; then
      exit 0
    fi
    exec colima start --profile "$PROFILE" --arch x86_64 --vm-type qemu \
      --cpus 4 --memory 8 --disk 40 --runtime docker --mount-type sshfs \
      --mount "$ROOT:w" --mount "$GIT_COMMON"
    ;;
  build)
    # The protocol trees come from a local Skills clone at the locked commits.
    [ -n "${SKILLS_REPO:-}" ] || refuse skills-repo-missing
    rm -rf "$ROOT/.protocol-trees"
    python3 "$ROOT/scripts/protocol_trees.py" export --skills-repo "$SKILLS_REPO" \
      --out "$ROOT/.protocol-trees"
    exec docker --context "$CONTEXT" build --platform linux/amd64 -f "$ROOT/containers/test.Dockerfile" \
      -t "$IMAGE" "$ROOT"
    ;;
  facts)
    docker_env run --rm --platform linux/amd64 --network none "$IMAGE" \
      python3 -c 'import os, platform; u = os.uname(); print("kernel=" + u.release); print("machine=" + u.machine); print("python=" + platform.python_version())'
    printf 'image=%s\n' "$(docker_env image inspect --format '{{.Id}}' "$IMAGE")"
    ;;
  run)
    shift
    [ "$#" -gt 0 ] || refuse command-missing
    exec docker --context "$CONTEXT" run --rm --platform linux/amd64 --network none \
      --user "$(id -u):$(id -g)" --env HOME=/tmp \
      --volume "$ROOT:$ROOT" --volume "$GIT_COMMON:$GIT_COMMON:ro" \
      --workdir "$ROOT" "$IMAGE" "$@"
    ;;
  *)
    refuse usage
    ;;
esac
