FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml ./
COPY trustverify ./trustverify
COPY scripts ./scripts
COPY fixtures ./fixtures
COPY tests ./tests
RUN pip install --no-cache-dir '.[dev]'
RUN useradd --create-home sandbox && mkdir /data && chown sandbox /data
USER sandbox
CMD ["python", "-m", "trustverify", "demo", "--directory", "/data/demo"]
