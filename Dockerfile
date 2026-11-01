# ---- build stage --------------------------------------------------------
# Same base as the runtime so wheels built here match its interpreter and musl.
FROM python:3.14-alpine AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_ROOT_USER_ACTION=ignore

WORKDIR /src

# Copy only what the package build needs (explicit, so local scan output /
# credentials / config can never enter the image).
COPY pyproject.toml README.md LICENSE requirements-lock.txt ./
COPY findmytakeover.py ./
COPY collector ./collector

# Install the locked dependency set, then the app itself, into one
# self-contained directory. The lock makes image builds reproducible; pip
# users get the ranges in pyproject.toml instead.
RUN pip install --no-cache-dir --target=/packages -r requirements-lock.txt \
 && pip install --no-cache-dir --target=/packages --no-deps .

# ---- runtime stage ------------------------------------------------------
# Alpine keeps the image small; build tooling stays behind in the builder.
# Runs as an unprivileged uid 65532 with HOME=/home/nonroot (same as the old
# distroless image, so existing credential mount paths keep working).
FROM python:3.14-alpine

ENV PYTHONPATH=/packages \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN adduser -D -u 65532 -h /home/nonroot nonroot

COPY --from=builder /packages /packages

WORKDIR /app
USER nonroot

# Config and read-only cloud credentials are supplied at runtime via mounts, e.g.:
#   docker run --rm \
#     -v "$PWD/findmytakeover.config:/app/findmytakeover.config:ro" \
#     -v "$HOME/.aws:/home/nonroot/.aws:ro" \
#     -v "$HOME/.config/gcloud:/home/nonroot/.config/gcloud:ro" \
#     -v "$HOME/.azure:/home/nonroot/.azure:ro" \
#     findmytakeover
ENTRYPOINT ["python", "-m", "findmytakeover"]
CMD ["--config-file", "/app/findmytakeover.config"]
