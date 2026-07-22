# ---- build stage --------------------------------------------------------
# Must match the distroless runtime's interpreter: distroless python3-debian13
# ships Python 3.13, so build the wheels against 3.13 on the same (trixie) libc.
FROM python:3.13-slim-trixie AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_ROOT_USER_ACTION=ignore

WORKDIR /src

# Copy only what the package build needs (explicit, so local scan output /
# credentials / config can never enter the image).
COPY pyproject.toml README.md LICENSE ./
COPY findmytakeover.py ./
COPY collector ./collector

# Install the app and all dependencies into one self-contained directory.
RUN pip install --no-cache-dir --target=/packages .

# ---- runtime stage ------------------------------------------------------
# Distroless: no shell, no package manager, no root — just the interpreter and
# our code. The :nonroot tag runs as uid 65532 with HOME=/home/nonroot.
FROM gcr.io/distroless/python3-debian13:nonroot

ENV PYTHONPATH=/packages \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY --from=builder /packages /packages

WORKDIR /app

# Config and read-only cloud credentials are supplied at runtime via mounts, e.g.:
#   docker run --rm \
#     -v "$PWD/findmytakeover.config:/app/findmytakeover.config:ro" \
#     -v "$HOME/.aws:/home/nonroot/.aws:ro" \
#     -v "$HOME/.config/gcloud:/home/nonroot/.config/gcloud:ro" \
#     -v "$HOME/.azure:/home/nonroot/.azure:ro" \
#     findmytakeover
#
# No shell in the image — run the module with the image's own interpreter.
ENTRYPOINT ["/usr/bin/python3", "-m", "findmytakeover"]
CMD ["--config-file", "/app/findmytakeover.config"]
