# The isolated validator: a read-only sandbox root filesystem and the trusted
# supervisor that runs it under gVisor. See adr/isolate-validator-trust.
#
# Stage `rootfs` is what a job sees: CPython 3.14.6, Git, GnuPG and ssh-keygen
# at exact Debian versions from the base image's own snapshot date, the two
# read-only protocol trees and the service's validation code. Every executable a
# native command runs is checked here and again on every attempt.
FROM --platform=linux/amd64 python:3.14.6-slim-trixie@sha256:b921fe7e7522f828d45197a47656ec465a9b15689b27fa8e1fba2864fca5b967 AS rootfs
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN sed -i \
      -e 's|^URIs: http://deb.debian.org/debian-security$|URIs: http://snapshot.debian.org/archive/debian-security/20260803T000000Z|' \
      -e 's|^URIs: http://deb.debian.org/debian$|URIs: http://snapshot.debian.org/archive/debian/20260803T000000Z|' \
      /etc/apt/sources.list.d/debian.sources \
    && apt-get -o Acquire::Check-Valid-Until=false update \
    && apt-get install -y --no-install-recommends git=1:2.47.3-0+deb13u1 \
       gpg=2.4.7-21+deb13u1+b4 gpgconf=2.4.7-21+deb13u1+b4 openssh-client=1:10.0p1-7+deb13u4 \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*.deb /var/log/apt /var/log/dpkg.log \
    && printf '%s  %s\n' \
       30a7def0b3e8d24a36d3829202717542bef124c0a40608b2232b7c837b271bc9 /usr/local/bin/python3.14 \
       88755a85309e86e4ae833edac25a7999ba8cb3a3d15a4a63ca1f229b8ef89423 /usr/local/lib/libpython3.14.so.1.0 \
       356db14e102d68a1a37d8a1ac577dfd678d45d46e92f468bef8b7154e7bfdc60 /usr/bin/git \
       7c9d2f9416aabcd10199e2984439f49612644a948279ac56bdf70d69c8958ddf /usr/bin/gpg \
       17ea11378c9d71166df855b73a66333fbf8095cb8da7d3a474bd325e3ca726db /usr/bin/gpgconf \
       4a16f170f7c80d6643d3ffada36d396c9d7b1d63238a218628e37af38d6107c0 /usr/bin/ssh-keygen \
       | sha256sum -c -
# Mount points for the job's private scratch, its sealed input and its trust
# document. The supervisor binds each one; nothing in them comes from the image.
RUN mkdir -p /job /input /trust /opt/fiat-checkpoints/service/src \
    && : > /input/checkpoint.zip && : > /trust/job.json
COPY .protocol-trees/authority /opt/fiat-checkpoints/protocol/authority
COPY .protocol-trees/native /opt/fiat-checkpoints/protocol/native
# The native commands run from a copy of the released native tree plus the one
# file its profile omits, `scripts/run_observation.py` at the same commit.
COPY .protocol-trees/native /opt/fiat-checkpoints/native-runtime
COPY .protocol-trees/native-extra/scripts/run_observation.py /opt/fiat-checkpoints/native-runtime/scripts/run_observation.py
RUN printf '%s  %s\n' 712f2afc40f7703cc64a92cd850559684a28f1b98e3241652a67ac6b48124d40 \
       /opt/fiat-checkpoints/native-runtime/scripts/run_observation.py | sha256sum -c -
COPY protocol.lock.json protocol.trees.json /opt/fiat-checkpoints/service/
COPY src/fiat_checkpoints /opt/fiat-checkpoints/service/src/fiat_checkpoints
RUN find /opt/fiat-checkpoints -name __pycache__ -prune -exec rm -rf {} + \
    && chmod -R a-w /opt/fiat-checkpoints /input /trust
USER 65532:65532

# Stage `supervisor` runs checks and the launcher. It needs root for runsc,
# cgroups and per-job tmpfs mounts, and it never runs archive-carried code.
FROM --platform=linux/amd64 python:3.14.6-slim-trixie@sha256:b921fe7e7522f828d45197a47656ec465a9b15689b27fa8e1fba2864fca5b967 AS supervisor
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    UV_NO_CACHE=1 UV_PYTHON_DOWNLOADS=never UV_PROJECT_ENVIRONMENT=/opt/venv
COPY requirements-tools.lock /build/requirements-tools.lock
RUN python -m pip install --disable-pip-version-check --no-cache-dir --require-hashes \
    --only-binary=:all: --no-deps --target /opt/tools -r /build/requirements-tools.lock
COPY pyproject.toml uv.lock .python-version /build/project/
RUN /opt/tools/bin/uv sync --project /build/project --locked --no-config \
    --no-install-project --python /usr/local/bin/python3.14 \
    && rm -rf /build
ENV PATH=/opt/venv/bin:/opt/tools/bin:$PATH UV_OFFLINE=1
# gVisor release 20261019.0, x86_64. The archive digest is checked on download
# and the runsc digest again here; the launcher checks runsc on every job.
ADD --checksum=sha256:1298e8ed9c3fee900f00d2ea96ec2d79d80ed93f2175812f29b7e7da718041a3 \
    https://storage.googleapis.com/gvisor/releases/release/20261019.0/x86_64/gvisor.tar.bz2 /build/gvisor.tar.bz2
RUN python3 -I -c "import hashlib, tarfile; \
d = open('/build/gvisor.tar.bz2', 'rb').read(); \
assert hashlib.sha512(d).hexdigest() == '7cbc2aeeee809dcccfb40e612504a1b76f2c119790cee59e482f7b35428cccc4f71705e7e322442d07d1f7d29b5d9e72e31319fc3088d6dcbec9fc7c1f0d8881'; \
t = tarfile.open('/build/gvisor.tar.bz2'); \
t.extractall('/opt/fiat-checkpoints/gvisor', members=[m for m in t.getmembers() if m.name == 'runsc' or m.name.startswith('gvisor-bin')], filter='data')" \
    && printf '%s  %s\n' \
       1ab7bb68955a028d3a82bac6406ee0f9ac0efaf2d6c49adef1d2448251d2b1131486674c0fe8c2599d680ccd04765f76040d1d8c202f8f9a49ea4c366494f266 /opt/fiat-checkpoints/gvisor/runsc \
       | sha512sum -c - \
    && chown -R 0:0 /opt/fiat-checkpoints/gvisor && chmod -R a-w,go-w /opt/fiat-checkpoints/gvisor \
    && rm -rf /build
COPY --from=rootfs / /opt/fiat-checkpoints/sandbox/rootfs
COPY .protocol-trees/authority /opt/fiat-checkpoints/protocol/authority
COPY .protocol-trees/native /opt/fiat-checkpoints/protocol/native
COPY protocol.lock.json protocol.trees.json /build/check/
COPY src/fiat_checkpoints /build/check/src/fiat_checkpoints
RUN chmod -R a-w /opt/fiat-checkpoints/protocol
# The loader refuses a tree its process could write, so the check runs as an
# unprivileged user here; the supervisor itself runs with a read-only root.
USER 65532:65532
RUN python3 -I -c "import sys; sys.path.insert(0, '/build/check/src'); \
from fiat_checkpoints.records.trees import load_release; \
print(load_release('/build/check', '/opt/fiat-checkpoints/protocol').lock_check['code'])"
USER 0:0
RUN rm -rf /build
CMD ["python3", "scripts/check.py", "--group", "validation,sandbox"]
