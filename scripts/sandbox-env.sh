#!/bin/sh
# Run the validation and sandbox checks in the pinned validator image.
#
#   scripts/sandbox-env.sh build        build the validator image (needs SKILLS_REPO)
#   scripts/sandbox-env.sh criterion-build
#                                       build the test-only criterion image from the
#                                       validator image (needs SKILLS_REPO)
#   scripts/sandbox-env.sh facts        print kernel, image id and the runsc pin
#   scripts/sandbox-env.sh run CMD...   run CMD as the supervisor at this checkout
#
# A run passes the validator, test and PostgreSQL image ids in as
# FIAT_IMAGE_VALIDATOR, FIAT_IMAGE_TEST and FIAT_IMAGE_POSTGRES, because a
# container cannot read its own image id; an absent image passes an empty value.
# FIAT_TEST_IMAGE names the test image (default fiat-checkpoints-test:local).
# FIAT_SANDBOX_IMAGE=criterion runs CMD in the criterion image instead
# (containers/criterion.Dockerfile), which the native-sequence-linux design
# resolver needs; the validator id passed in stays the validator image's.
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
VALIDATOR_IMAGE=${FIAT_VALIDATOR_IMAGE:-fiat-checkpoints-validator:local}
CRITERION_IMAGE=${FIAT_CRITERION_IMAGE:-fiat-checkpoints-criterion:local}
case "${FIAT_SANDBOX_IMAGE:-validator}" in
  validator) IMAGE=$VALIDATOR_IMAGE ;;
  criterion) IMAGE=$CRITERION_IMAGE ;;
  *) printf 'sandbox-env-refused: %s\n' sandbox-image-unknown >&2; exit 2 ;;
esac
TEST_IMAGE=${FIAT_TEST_IMAGE:-fiat-checkpoints-test:local}
POSTGRES_VOLUME=fiat-checkpoints-postgres-socket
POSTGRES_CONTAINER=fiat-checkpoints-postgres
NATIVE_COMMIT=1d4e4eebcba1825d0eb3192bf08a6c509bdc0d74
CRITERION_COMMIT=685158cdc5407ca5559bf9ef4a021d664e764ece

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
      -f "$ROOT/containers/validator.Dockerfile" -t "$VALIDATOR_IMAGE" "$ROOT"
    ;;
  criterion-build)
    [ -n "${SKILLS_REPO:-}" ] || refuse skills-repo-missing
    # BuildKit reads a bare image id in FROM as a registry name, so the build
    # names the validator tag, and the result must sit on the layers that tag
    # had before the build.
    VALIDATOR_LAYERS=$(docker --context "$CONTEXT" image inspect --format '{{range .RootFS.Layers}}{{println .}}{{end}}' \
      "$VALIDATOR_IMAGE") || refuse validator-image-missing
    [ -n "$VALIDATOR_LAYERS" ] || refuse validator-image-missing
    # Each listed file comes from the commit its tree names; the image build
    # checks every digest and refuses any file the list does not name.
    rm -rf "$ROOT/.protocol-trees/criterion" "$ROOT/.protocol-trees/criterion.sha256"
    while read -r digest path; do
      case "$path" in
        root/*) commit=$CRITERION_COMMIT ;;
        native-source/*) commit=$NATIVE_COMMIT ;;
        *) refuse criterion-list-invalid ;;
      esac
      mkdir -p "$(dirname -- "$ROOT/.protocol-trees/criterion/$path")"
      git -C "$SKILLS_REPO" show "$commit:${path#*/}" > "$ROOT/.protocol-trees/criterion/$path" \
        || refuse criterion-file-missing
    done < "$ROOT/containers/criterion.sha256"
    cp "$ROOT/containers/criterion.sha256" "$ROOT/.protocol-trees/criterion.sha256"
    docker --context "$CONTEXT" build --platform linux/amd64 \
      --build-arg VALIDATOR_IMAGE="$VALIDATOR_IMAGE" \
      -f "$ROOT/containers/criterion.Dockerfile" -t "$CRITERION_IMAGE" "$ROOT"
    CRITERION_LAYERS=$(docker --context "$CONTEXT" image inspect \
      --format '{{range .RootFS.Layers}}{{println .}}{{end}}' "$CRITERION_IMAGE") \
      || refuse criterion-image-missing
    count=$(printf '%s\n' "$VALIDATOR_LAYERS" | grep -c .)
    if [ "$(printf '%s\n' "$CRITERION_LAYERS" | grep . | head -n "$count")" != \
         "$(printf '%s\n' "$VALIDATOR_LAYERS" | grep .)" ] \
       || [ "$(printf '%s\n' "$CRITERION_LAYERS" | grep -c .)" -le "$count" ]; then
      docker --context "$CONTEXT" image rm "$CRITERION_IMAGE" >/dev/null 2>&1 || true
      refuse criterion-base-changed
    fi
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
    VALIDATOR_ID=$(docker --context "$CONTEXT" image inspect --format '{{.Id}}' "$VALIDATOR_IMAGE" \
      2>/dev/null || true)
    TEST_ID=$(docker --context "$CONTEXT" image inspect --format '{{.Id}}' "$TEST_IMAGE" 2>/dev/null || true)
    POSTGRES_ID=$(docker --context "$CONTEXT" container inspect --format '{{.Image}}' "$POSTGRES_CONTAINER" \
      2>/dev/null || true)
    exec docker --context "$CONTEXT" run --rm --platform linux/amd64 --network none \
      --privileged --cgroupns private --read-only --tmpfs /tmp:rw,exec,size=1g \
      --tmpfs /run:rw,size=2g --env HOME=/tmp \
      --env FIAT_IMAGE_VALIDATOR="$VALIDATOR_ID" --env FIAT_IMAGE_TEST="$TEST_ID" \
      --env FIAT_IMAGE_POSTGRES="$POSTGRES_ID" \
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
