# syntax=docker/dockerfile:1
#
# Build:  docker build -t passcheck .
# Run:    docker run --rm -it passcheck                # hidden interactive prompt
#         docker run --rm -it passcheck --pwned        # plus the breach check
#         printf '%s\n' "$PW" | docker run --rm -i passcheck --stdin --json

ARG PYTHON_IMAGE=python:3.13-slim@sha256:2d44738ebf4ce5f63b9d9ea871e9c7cfdc0426f7b0c97cac915fd88ded1d86bb

# ---- build stage: turn the source tree into a wheel --------------------------------
FROM ${PYTHON_IMAGE} AS build
WORKDIR /src
COPY pyproject.toml README.md ./
COPY passcheck ./passcheck
RUN pip wheel --no-cache-dir --no-deps --wheel-dir /wheels .

# ---- runtime stage: just the installed package, running as an unprivileged user ----
FROM ${PYTHON_IMAGE}
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1
RUN --mount=type=bind,from=build,source=/wheels,target=/wheels \
    pip install --no-cache-dir /wheels/*.whl \
    && useradd --create-home --shell /usr/sbin/nologin --uid 10001 passcheck
USER passcheck
WORKDIR /home/passcheck
ENTRYPOINT ["passcheck"]
