# Outrider web portal in a container.
#
# Build:  docker build -t outrider-recon .
# Run:    docker run --rm --network host outrider-recon
#         then open http://127.0.0.1:8765
#
# Outrider binds loopback only by design (it refuses non-loopback hosts), so the
# container shares the host loopback via `--network host` (Linux). We do NOT bind
# 0.0.0.0 — that would violate Outrider's own security posture and fail its
# release audit. On macOS/Windows Docker Desktop, `--network host` is limited;
# prefer the native `./bootstrap.sh` path there.
#
# Persist runs across container restarts by mounting a volume:
#   docker run --rm --network host -v "$PWD/runs:/home/outrider/runs" outrider-recon
FROM python:3.12-slim

ENV PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /src
COPY . /src

# Non-editable install so the runtime does not depend on the source tree; the
# packaged skill catalog, schemas, web static assets, and benchmark corpus ship
# as package data.
RUN python -m pip install --upgrade pip \
    && python -m pip install ".[web]" \
    && useradd --create-home --uid 10001 outrider

USER outrider
WORKDIR /home/outrider
EXPOSE 8765

# Loopback-only bind; reach it from the host with `--network host`.
CMD ["outrider", "--no-browser", "--host", "127.0.0.1", "--port", "8765"]
