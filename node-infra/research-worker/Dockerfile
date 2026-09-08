# MMR research worker image. The build context is the local repository root;
# see docker-compose.yml and Dockerfile.dockerignore.
ARG PYTHON_IMAGE=python:3.12-slim-bookworm
FROM ${PYTHON_IMAGE}

ARG MMR_SOURCE_REVISION=working-tree

# Classifiers verify the mounted checkout revision and clean Git/LFS state.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git git-lfs \
    && rm -rf /var/lib/apt/lists/*

ENV VIRTUAL_ENV=/opt/venv \
    PATH="/opt/venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN python -m venv /opt/venv

WORKDIR /opt/mmr-build
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir .

RUN useradd --create-home --uid 1000 --user-group research

LABEL org.opencontainers.image.title="Merge Mining Research worker" \
      org.opencontainers.image.source-revision="${MMR_SOURCE_REVISION}"

WORKDIR /opt/merge-mining-research
USER research

# A harmless default makes accidental starts observable and exits immediately.
# Jobs are always supplied explicitly by the operator.
CMD ["python", "--version"]
