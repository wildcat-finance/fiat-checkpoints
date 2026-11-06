#!/bin/sh
# Run the validation and sandbox checks in the pinned validator image.
#
#   scripts/sandbox-env.sh build        build the validator image (needs SKILLS_REPO)
#   scripts/sandbox-env.sh facts        print kernel, image id and the runsc pin
#   scripts/sandbox-env.sh run CMD...   run CMD as the supervisor at this checkout
#
# The supervisor starts gVisor `runsc`, so it runs as root in a privileged
# container on the same colima profile as scripts/linux-env.sh. That container
# has no network and a read-only root, so the protocol trees are unwritable even
# to root; /tmp and /run are private tmpfs. Each job inside it gets its own
# gVisor sandbox with no network either. Before CMD runs, the container moves itself out of its root cgroup so
# that per-job cgroups can take the memory, pids and cpu controllers.
set -eu

PROFILE=fiat-s862a
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
GIT_COMMON=$(git -C "$ROOT" rev-parse --path-format=absolute --git-common-dir)
CONTEXT=${DOCKER_CONTEXT:-colima-$PROFILE}
IMAGE=${FIAT_VALIDATOR_IMAGE:-fiat-checkpoints-validator:local}
POSTGRES_VOLUME=fiat-checkpoints-postgres-socket
NATIVE_COMMIT=1d4e4eebcba1825d0eb3192bf08a6c509bdc0d74

refuse() {
  printf 'sandbox-env-refused: %s\n' "$1" >&2
  exit 2
}

case "${1:-}" in
  build)
    [ -n "${SKILLS_REPO:-}" ] || refuse skills-repo-missing
    rm -rf "$ROOT/.protocol-trees"
    python3 "$ROOT/scripts/protocol_trees.py" export --skills-repo "$SKILLS_REPO" \
      --out "$ROOT/.protocol-trees"
    # The released native profile omits the observation validator that restore,
    # verify and identity import; it comes from the same native commit and the
    # image build checks its digest (adr/isolate-validator-trust).
    mkdir -p "$ROOT/.protocol-trees/native-extra/scripts"
    git -C "$SKILLS_REPO" show "$NATIVE_COMMIT:scripts/run_observation.py" \
      > "$ROOT/.protocol-trees/native-extra/scripts/run_observation.py"
    exec docker --context "$CONTEXT" build --platform linux/amd64 \
      -f "$ROOT/containers/validator.Dockerfile" -t "$IMAGE" "$ROOT"
    ;;
  facts)
    docker --context "$CONTEXT" run --rm --platform linux/amd64 --network none "$IMAGE" \
      /opt/fiat-checkpoints/gvisor/runsc --version
    printf 'kernel=%s\n' "$(docker --context "$CONTEXT" info --format '{{.KernelVersion}}')"
    printf 'image=%s\n' "$(docker --context "$CONTEXT" image inspect --format '{{.Id}}' "$IMAGE")"
    ;;
  run)
    shift
    [ "$#" -gt 0 ] || refuse command-missing
    exec docker --context "$CONTEXT" run --rm --platform linux/amd64 --network none \
      --privileged --cgroupns private --read-only --tmpfs /tmp:rw,exec,size=1g \
      --tmpfs /run:rw,size=2g --env HOME=/tmp \
      --env FIAT_TEST_POSTGRES=/run/fiat-postgres --volume "$POSTGRES_VOLUME:/run/fiat-postgres" \
      --volume "$ROOT:$ROOT" --volume "$GIT_COMMON:$GIT_COMMON:ro" \
      --workdir "$ROOT" "$IMAGE" /bin/sh -c '
        mkdir -p /sys/fs/cgroup/supervisor &&
        echo $$ > /sys/fs/cgroup/supervisor/cgroup.procs &&
        echo "+cpu +memory +pids" > /sys/fs/cgroup/cgroup.subtree_control &&
        exec "$@"' sandbox-env "$@"
    ;;
  *)
    refuse usage
    ;;
esac
