FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ src/

ENV PYTHONUNBUFFERED=1

CMD ["python", "-c", "from src.sentinel.handler import DriftSentinel; print('Sentinel Loaded')"]
