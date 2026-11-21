FROM python:3.12-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONPATH=/app
ENV DATA_DIR=/app/data

# Use UID/GID 1000 to match host user permissions cleanly
RUN groupadd -g 1000 hunter && useradd -u 1000 -g hunter -m hunter && \
    mkdir -p /app/data && chown -R hunter:hunter /app

COPY requirements.txt requirements-dev.txt ./
RUN pip install --no-cache-dir -r requirements.txt -r requirements-dev.txt

COPY src/ ./src/
COPY tests/ ./tests/
COPY config.yaml ./config.yaml

RUN chown -R hunter:hunter /app

USER hunter

CMD ["python", "-m", "src.main"]
