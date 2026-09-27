FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .

RUN pip install \
    --no-cache-dir \
    --disable-pip-version-check \
    --only-binary :all: \
    -r requirements.txt

COPY . .

EXPOSE 5000

# --timeout must stay >= OLLAMA_TIMEOUT (see .env), or gunicorn will
# kill the worker before a slow Ollama response comes back.
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--threads", "4", "--timeout", "300", "app:app"]