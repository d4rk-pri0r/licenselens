FROM python:3.12-slim
LABEL org.opencontainers.image.source="https://github.com/d4rk-pri0r/licenselens"
LABEL org.opencontainers.image.description="Security License Lens — detect Microsoft security configuration debt: capabilities you pay for but leave unused."
LABEL org.opencontainers.image.licenses="MIT"

ENV PYTHONUNBUFFERED=1
ENV PIP_NO_CACHE_DIR=1
WORKDIR /app

COPY pyproject.toml README.md LICENSE* ./
COPY src ./src
COPY checks ./checks
COPY catalog ./catalog
COPY templates ./templates

RUN pip install --upgrade pip && pip install .

# Reports land in /reports; mount a host directory there for dry-run or live scans.
RUN mkdir /reports
WORKDIR /reports

ENTRYPOINT ["licenselens"]
CMD ["demo", "-o", "/reports"]
