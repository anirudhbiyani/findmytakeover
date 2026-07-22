FROM python:3.14-slim

# Fail fast, no stray .pyc, no pip cache/version-check noise.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_ROOT_USER_ACTION=ignore

WORKDIR /app

# Copy only what the package build needs (explicit, so local scan output /
# credentials / config can never be baked into the image), install as root
# into the system site-packages, then drop privileges for runtime.
COPY pyproject.toml README.md LICENSE ./
COPY findmytakeover.py ./
COPY collector ./collector
RUN pip install --no-cache-dir .

# Run as an unprivileged, no-login user (its home holds the mounted CLI creds).
RUN useradd --create-home --shell /usr/sbin/nologin --uid 10001 scanner
USER scanner

# Config and read-only cloud credentials are supplied at runtime via mounts, e.g.:
#   docker run --rm \
#     -v "$PWD/findmytakeover.config:/app/findmytakeover.config:ro" \
#     -v "$HOME/.aws:/home/scanner/.aws:ro" \
#     -v "$HOME/.config/gcloud:/home/scanner/.config/gcloud:ro" \
#     -v "$HOME/.azure:/home/scanner/.azure:ro" \
#     findmytakeover
ENTRYPOINT ["findmytakeover"]
CMD ["--config-file", "/app/findmytakeover.config"]
