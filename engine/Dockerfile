# ── Stage 1: Builder ─────────────────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

# System deps for compilation
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential curl git \
    && rm -rf /var/lib/apt/lists/*

# Install Foundry (forge, cast, anvil)
RUN curl -L https://foundry.paradigm.xyz | bash \
    && /root/.foundry/bin/foundryup

# Copy dependency spec first for layer caching
COPY pyproject.toml ./
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir .[dev]

# Copy full source
COPY . .


# ── Stage 2: Runtime ────────────────────────────────────────────────────────
FROM python:3.12-slim AS runtime

WORKDIR /app

# Runtime system deps (includes WeasyPrint requirements: cairo, pango, etc.)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq-dev \
    libcairo2 libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf2.0-0 \
    libffi-dev shared-mime-info fonts-liberation \
    && rm -rf /var/lib/apt/lists/*

# Copy Foundry binaries from builder
COPY --from=builder /root/.foundry/bin/forge /usr/local/bin/forge
COPY --from=builder /root/.foundry/bin/cast /usr/local/bin/cast
COPY --from=builder /root/.foundry/bin/anvil /usr/local/bin/anvil

# Copy Python packages from builder
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application source
COPY . .

# Create non-root user
RUN groupadd -r zaseon && useradd -r -g zaseon -d /app zaseon \
    && chown -R zaseon:zaseon /app

# Create temp/cache directories
RUN mkdir -p /tmp/zaseon_soul /tmp/zaseon_soul_corpus \
    && chown -R zaseon:zaseon /tmp/zaseon_soul /tmp/zaseon_soul_corpus

USER zaseon

# Health check
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD curl -f http://localhost:8000/api/health || exit 1

EXPOSE 8000

# Default: run API server
CMD ["uvicorn", "engine.api.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
