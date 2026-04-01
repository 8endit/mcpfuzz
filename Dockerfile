FROM python:3.12-slim

WORKDIR /app

# Install mcpfuzz and its dev dependencies
COPY pyproject.toml LICENSE ./
COPY src/ src/
COPY patterns/ patterns/
COPY tests/ tests/
COPY demo_servers/ demo_servers/

RUN pip install --no-cache-dir -e ".[dev]"

# Non-root user for additional isolation
RUN useradd --create-home --shell /bin/bash fuzzer
USER fuzzer

ENTRYPOINT ["mcpfuzz"]
