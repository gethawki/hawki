# --------------------
# File: docker/Dockerfile
# --------------------
# Multi-stage build for Hawk-i CLI

# ---- Builder stage ----
FROM python:3.11-slim AS builder

WORKDIR /build

# Copy only dependency files first for better caching
COPY pyproject.toml requirements.txt README.md ./
COPY hawki/ ./hawki/
COPY cli/ ./cli/
COPY scripts/ ./scripts/

# Build wheel
RUN pip install --upgrade pip build && \
    python -m build --wheel

# ---- Final stage ----
FROM python:3.11-slim

# Install runtime dependencies. curl + ca-certificates are required by the
# Node and Foundry install steps below (python:3.11-slim ships neither); git is
# used by the deep agent's repo watcher and remote-clone path.
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user
RUN useradd --create-home hawki
WORKDIR /home/hawki

# Copy the wheel from builder
COPY --from=builder /build/dist/*.whl /tmp/

# Install the wheel with the reports extra so HTML and chart reports work out of
# the box (jinja2 + matplotlib); without it those formats are disabled.
RUN WHL="$(ls /tmp/*.whl)" && \
    pip install --no-cache-dir "${WHL}[reports]" && \
    rm /tmp/*.whl

# Install Node.js for Hardhat (optional but good)
RUN curl -fsSL https://deb.nodesource.com/setup_18.x | bash - \
    && apt-get install -y nodejs \
    && rm -rf /var/lib/apt/lists/*

# Install Foundry into a shared location and expose it on PATH for every user.
# Installing under /root and ending on USER hawki would leave forge/anvil off
# the runtime user's PATH, so Foundry lives in /opt/foundry instead.
ENV FOUNDRY_DIR="/opt/foundry"
ENV PATH="/opt/foundry/bin:${PATH}"
RUN curl -L https://foundry.paradigm.xyz | bash \
    && foundryup \
    && chmod -R a+rx /opt/foundry

# Ensure the hawki command is available
USER hawki

ENTRYPOINT ["hawki"]
CMD ["--help"]