FROM python:3.12-slim

# Install uv for fast dependency management
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

WORKDIR /app

# Copy dependency files first for layer caching
COPY pyproject.toml uv.lock ./

# Install project dependencies
RUN uv sync --frozen --no-install-project

# Copy source code
COPY src ./src
COPY README.md .python-version ./

# Install the application
RUN uv sync --frozen

ENV PATH="/app/.venv/bin:$PATH"

CMD ["python", "-m", "graduation_project.main"]

