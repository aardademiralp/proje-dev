# Multi-stage Dockerfile
# Stage 1: Build Rust Core Engine if source exists, otherwise create dummy
FROM rust:1.75-slim AS builder
WORKDIR /build
COPY core_engine/ ./core_engine/
RUN mkdir -p target/release && \
    if [ -f core_engine/Cargo.toml ]; then \
        cd core_engine && cargo build --release && cp target/release/isu-secops-engine ../target/release/; \
    else \
        echo "Placeholder binary since core_engine is built externally" && \
        touch target/release/isu-secops-engine; \
    fi

# Stage 2: Final Runtime Image
FROM python:3.11-slim
WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy built engine binary
COPY --from=builder /build/target/release/isu-secops-engine /usr/local/bin/isu-secops-engine
RUN chmod +x /usr/local/bin/isu-secops-engine

# Copy dependencies manifest
COPY pyproject.toml .
COPY README.md .

# Install application dependencies
RUN pip install --no-cache-dir .

# Copy application code
COPY orchestrator/ ./orchestrator/

# Expose FastAPI port
EXPOSE 8000

# Set environment variables
ENV ISU_ENGINE_PATH=/usr/local/bin/isu-secops-engine
ENV APP_ENV=production
ENV HOST=0.0.0.0
ENV PORT=8000

# Run FastAPI app
CMD ["uvicorn", "orchestrator.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
