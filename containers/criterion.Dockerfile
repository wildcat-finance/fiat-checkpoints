# The test-only criterion image: the validator image plus the released native
# criterion and gpg-agent in the sandbox root filesystem, so the
# native-sequence-linux design resolver can run the criterion itself in a gVisor
# job. Production never uses it; the validator image is unchanged.
#
#   SKILLS_REPO=<skills clone> scripts/sandbox-env.sh criterion-build
#
# The launcher exports every file `containers/criterion.sha256` names: `root/`
# from Skills 685158cdc5407ca5559bf9ef4a021d664e764ece (native_conformance's
# SOURCES, FILES and MANIFEST, conformance's declared inputs and every module
# they import) and `native-source/` from native commit
# 1d4e4eebcba1825d0eb3192bf08a6c509bdc0d74 (the 238-file native profile,
# scripts/run_observation.py, the two native tests native-capabilities.json pins
# and the modules they import). The build refuses unless the list is that
# file, every file matches it and nothing else is present. The launcher builds
# FROM the validator tag and then refuses the image unless its layers begin with
# every layer that tag had before the build.
ARG VALIDATOR_IMAGE=fiat-checkpoints-validator:local

# gpg-agent 2.4.7-21+deb13u1+b4, the version of the image's gpg, from the same
# Debian snapshot, checked by package digest. The hostile cases generate their
# fixture signing key through it; the native validation sequence never does.
FROM --platform=linux/amd64 python:3.14.6-slim-trixie@sha256:b921fe7e7522f828d45197a47656ec465a9b15689b27fa8e1fba2864fca5b967 AS agent
RUN sed -i \
      -e 's|^URIs: http://deb.debian.org/debian-security$|URIs: http://snapshot.debian.org/archive/debian-security/20260803T000000Z|' \
      -e 's|^URIs: http://deb.debian.org/debian$|URIs: http://snapshot.debian.org/archive/debian/20260803T000000Z|' \
      /etc/apt/sources.list.d/debian.sources \
    && apt-get -o Acquire::Check-Valid-Until=false update \
    && mkdir /build && cd /build \
    && apt-get download gpg-agent=2.4.7-21+deb13u1+b4 \
    && printf '%s  %s\n' f67b953b03d7394d83e1e022bc548f4553d0cec20c83b90e9832666235f89631 \
       gpg-agent_2.4.7-21+deb13u1+b4_amd64.deb | sha256sum -c - \
    && dpkg-deb -x gpg-agent_2.4.7-21+deb13u1+b4_amd64.deb /build/agent

FROM ${VALIDATOR_IMAGE}
USER 0:0
COPY .protocol-trees/criterion.sha256 /opt/fiat-checkpoints/criterion.sha256
COPY .protocol-trees/criterion /opt/fiat-checkpoints/sandbox/rootfs/opt/fiat-checkpoints/criterion
# Only the agent binary: its libraries are already in the root filesystem, and
# loopback key generation needs no pinentry.
COPY --from=agent /build/agent/usr/bin/gpg-agent /opt/fiat-checkpoints/sandbox/rootfs/usr/bin/gpg-agent
RUN printf '%s  %s\n' 4e10531a2e6cff10f1d9db3860a3681d6e1ec0d0a10fa5226d1d3ebd7391f7a3 \
       /opt/fiat-checkpoints/criterion.sha256 | sha256sum -c - \
    && cd /opt/fiat-checkpoints/sandbox/rootfs/opt/fiat-checkpoints/criterion \
    && sha256sum --strict --quiet -c /opt/fiat-checkpoints/criterion.sha256 \
    && test -z "$(find . ! -type f ! -type d)" \
    && find . -type f | sed 's|^\./||' | LC_ALL=C sort > /tmp/present \
    && awk '{print $2}' /opt/fiat-checkpoints/criterion.sha256 | LC_ALL=C sort > /tmp/listed \
    && cmp /tmp/present /tmp/listed && rm /tmp/present /tmp/listed \
    && chown -R 0:0 /opt/fiat-checkpoints/sandbox/rootfs/opt/fiat-checkpoints/criterion \
       /opt/fiat-checkpoints/sandbox/rootfs/usr/bin/gpg-agent /opt/fiat-checkpoints/criterion.sha256 \
    && chmod -R a-w,go-w /opt/fiat-checkpoints/sandbox/rootfs/opt/fiat-checkpoints/criterion \
       /opt/fiat-checkpoints/criterion.sha256 \
    && chmod 0555 /opt/fiat-checkpoints/sandbox/rootfs/usr/bin/gpg-agent
