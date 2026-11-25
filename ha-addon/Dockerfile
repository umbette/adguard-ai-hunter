ARG BUILD_FROM
FROM ${BUILD_FROM}

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    TLD_CACHE_DIR="/data/.tld_cache"

WORKDIR /app

# Install build dependencies for c-extensions and Pillow
RUN apk add --no-cache \
    gcc \
    musl-dev \
    libffi-dev \
    zlib-dev \
    jpeg-dev \
    sqlite \
    sqlite-dev

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ /app/src/
COPY sources/ /app/sources/
COPY filters/ /app/filters/
COPY extension/icons/ /app/extension/icons/

RUN mkdir -p /app/data /data/.tld_cache && chmod -R 755 /app

# Run Sentinel Core daemon
CMD ["python3", "-m", "src.main"]
