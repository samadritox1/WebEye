
FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PIP_NO_CACHE_DIR=1
ENV WEBEYE_DATA_DIR=/var/data
ENV PHISHPULSE_BROWSER_PATH=/usr/bin/chromium

WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        chromium \
        ca-certificates \
        fonts-liberation \
        tini && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /var/data /var/data/sandbox_screenshots && \
    useradd --create-home --uid 10001 webeye && \
    chown -R webeye:webeye /app /var/data

USER webeye

EXPOSE 10000

ENTRYPOINT ["/usr/bin/tini", "--"]

CMD ["sh", "-c", "exec uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-10000}"]
