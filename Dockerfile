FROM python:3.12-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONPATH=/app
ENV DATA_DIR=/app/data

# Use UID/GID 1000 to match host user permissions cleanly
RUN groupadd -g 1000 sentinel && useradd -u 1000 -g sentinel -m sentinel && \
    mkdir -p /app/data && chown -R sentinel:sentinel /app

COPY requirements.txt requirements-dev.txt ./
RUN pip install --no-cache-dir -r requirements.txt -r requirements-dev.txt

COPY src/ ./src/
COPY sources/ ./sources/
COPY filters/ ./filters/
COPY extension/icons/ ./extension/icons/
COPY tests/ ./tests/
COPY config.example.yaml ./config.yaml

RUN chown -R sentinel:sentinel /app

USER sentinel

CMD ["python", "-m", "src.main"]
