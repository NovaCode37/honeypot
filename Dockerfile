FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl-dev gcc curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p data \
    && groupadd -r honeyshield && useradd -r -g honeyshield honeyshield \
    && chown -R honeyshield:honeyshield /app

USER honeyshield

EXPOSE 2222 8080 2121 5000

CMD ["gunicorn", "-k", "eventlet", "-w", "1", "-b", "0.0.0.0:5000", "--timeout", "120", "wsgi:app"]
