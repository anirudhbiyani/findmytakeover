FROM python:3.14-slim

WORKDIR /app

COPY . /app
RUN pip install --no-cache-dir .

# Config and cloud credentials are provided at runtime via volume mounts, e.g.:
#   docker run --rm \
#     -v "$PWD/findmytakeover.config:/app/findmytakeover.config" \
#     -v "$HOME/.aws:/root/.aws:ro" \
#     findmytakeover
ENTRYPOINT ["findmytakeover"]
CMD ["--config-file", "/app/findmytakeover.config"]
