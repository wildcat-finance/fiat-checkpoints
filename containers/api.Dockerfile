FROM --platform=linux/amd64 python:3.14.6-slim-trixie@sha256:b921fe7e7522f828d45197a47656ec465a9b15689b27fa8e1fba2864fca5b967
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.lock /app/requirements.lock
RUN python -m pip install --disable-pip-version-check --no-cache-dir --require-hashes --only-binary=:all: -r requirements.lock
COPY src /app/src
COPY scripts/serve.py /app/scripts/serve.py
COPY config/container.json /app/config/container.json
USER 65532:65532
EXPOSE 8000
CMD ["python", "-I", "scripts/serve.py", "--config", "config/container.json"]
