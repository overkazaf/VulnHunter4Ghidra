FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/vulnhunter
COPY pyproject.toml README.md ./
COPY python ./python
COPY rules ./rules

RUN pip install --no-cache-dir .

WORKDIR /workspace
ENTRYPOINT ["vulnhunter"]
CMD ["--help"]
