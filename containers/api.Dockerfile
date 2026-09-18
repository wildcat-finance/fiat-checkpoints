FROM --platform=linux/amd64 python:3.12.13-slim-bookworm@sha256:6e13e65c55e33adf203d77ee371cf8bf5d81bd4902ef07565721f46bf44917af
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
