# The Linux test environment. The checkout is mounted at run time, never copied.
FROM --platform=linux/amd64 python:3.14.6-slim-trixie@sha256:b921fe7e7522f828d45197a47656ec465a9b15689b27fa8e1fba2864fca5b967
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
# The two protocol trees come from `scripts/protocol_trees.py export`, which
# checks every file against protocol.trees.json. They stay root-owned and
# read-only; the build refuses unless the service loader accepts them as the
# unprivileged user, including the released `lock` check.
COPY .protocol-trees/authority /opt/fiat-checkpoints/protocol/authority
COPY .protocol-trees/native /opt/fiat-checkpoints/protocol/native
COPY protocol.lock.json protocol.trees.json /build/check/
COPY src/fiat_checkpoints /build/check/src/fiat_checkpoints
RUN chmod -R a-w /opt/fiat-checkpoints/protocol
USER 65532:65532
RUN python3 -I -c "import sys; sys.path.insert(0, '/build/check/src'); \
from fiat_checkpoints.records.trees import load_release; \
print(load_release('/build/check', '/opt/fiat-checkpoints/protocol').lock_check['code'])"
USER 0:0
RUN rm -rf /build
USER 65532:65532
CMD ["python3", "scripts/check.py", "--group", "scaffold"]
