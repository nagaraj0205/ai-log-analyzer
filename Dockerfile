FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN groupadd --gid 10001 appgroup \
    && useradd \
        --uid 10001 \
        --gid appgroup \
        --create-home \
        --shell /usr/sbin/nologin \
        appuser

COPY requirements.txt .

RUN pip install \
    --no-cache-dir \
    --disable-pip-version-check \
    -r requirements.txt

COPY app.py .
COPY templates ./templates
COPY static ./static

RUN chown -R appuser:appgroup /app

USER appuser

EXPOSE 5000

HEALTHCHECK \
    --interval=30s \
    --timeout=5s \
    --start-period=10s \
    --retries=3 \
    CMD python -c \
    "import urllib.request; urllib.request.urlopen('http://localhost:5000/health', timeout=3)"

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--threads", "4", "--timeout", "240", "app:app"]