#!/bin/sh
# Start or stop the disposable PostgreSQL 16 server that checks connect to.
#
#   scripts/test-postgres.sh start    run the pinned server and wait until ready
#   scripts/test-postgres.sh stop     remove the server and its socket volume
#
# The server has no network: it listens only on a Unix socket in the named
# volume, which a test container mounts at /run/fiat-postgres. Its data lives
# in tmpfs and holds only synthetic check data. Docker's own DOCKER_CONTEXT
# selects the engine, so scripts/linux-env.sh and CI share these pins.
set -eu

IMAGE=postgres:16.15-trixie@sha256:1a6ab3f5345eb6dbe04a1349529caabdb0ab09293a09590fad07b2246bfa4b54
CONTAINER=fiat-checkpoints-postgres
VOLUME=fiat-checkpoints-postgres-socket

refuse() {
  printf 'test-postgres-refused: %s\n' "$1" >&2
  exit 2
}

case "${1:-}" in
  start)
    if [ "$(docker container inspect --format '{{.State.Running}}' "$CONTAINER" 2>/dev/null || true)" = true ]; then
      exit 0
    fi
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
    docker volume create "$VOLUME" >/dev/null
    # Local socket connections are trusted; nothing else can reach the server.
    docker run --detach --name "$CONTAINER" --platform linux/amd64 --network none \
      --user 999:999 --tmpfs /var/lib/postgresql/data:rw,uid=999,gid=999,mode=0700 \
      --volume "$VOLUME:/var/run/postgresql" --entrypoint /bin/sh "$IMAGE" -c \
      'initdb --pgdata=/var/lib/postgresql/data/cluster --username=postgres --auth-local=trust --auth-host=reject --encoding=UTF8 --no-locale >/dev/null && exec postgres -D /var/lib/postgresql/data/cluster -c listen_addresses= -c unix_socket_directories=/var/run/postgresql -c unix_socket_permissions=0777 -c max_connections=200' \
      >/dev/null
    tries=0
    until docker exec "$CONTAINER" pg_isready --quiet --host /var/run/postgresql --username postgres; do
      tries=$((tries + 1))
      [ "$tries" -lt 60 ] || refuse server-not-ready
      sleep 1
    done
    ;;
  stop)
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
    docker volume rm "$VOLUME" >/dev/null 2>&1 || true
    ;;
  *)
    refuse usage
    ;;
esac
