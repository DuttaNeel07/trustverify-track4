FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml ./
COPY trustverify ./trustverify
COPY track4_service.py threat-model.json ./
COPY scripts ./scripts
COPY fixtures ./fixtures
COPY tests ./tests
RUN pip install --no-cache-dir '.[messaging,dev]'
RUN useradd --create-home sandbox && mkdir /data && chown sandbox /data
USER sandbox
CMD ["python", "-m", "trustverify", "demo", "--directory", "/data/demo"]
