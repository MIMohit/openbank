# Build from binding/harness:  docker build -f pdp/Dockerfile -t bh-pdp:latest .
# Carries the reference verifier package (verifier.core/canon/jose) plus the PDP policy layer.
FROM python:3.12.8-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PORT=9100 \
    LOG_PATH=/logs/verifier.jsonl PDP_LOG_PATH=/logs/pdp.jsonl \
    AS_PUB_JWK=/app/keys/as_pub.jwk HTU_CANON=rfc3986 JTI_CACHE=on IAT_WINDOW=60 VIEW_MAC=off \
    POLICY=allowlist POLICY_NORMALIZE=off
WORKDIR /app
COPY pdp/requirements.txt /app/pdp/requirements.txt
RUN pip install --no-cache-dir -r /app/pdp/requirements.txt
# reference verifier (the PDP imports verifier.core and verifier.canon)
COPY verifier/__init__.py verifier/core.py verifier/canon.py verifier/jose.py /app/verifier/
# pdp layer
COPY pdp/__init__.py pdp/policy.py pdp/server.py /app/pdp/
COPY keys/as_pub.jwk /app/keys/as_pub.jwk
RUN useradd -r -u 10001 pdp && mkdir -p /logs && chown pdp /logs
USER pdp
EXPOSE 9100
HEALTHCHECK --interval=5s --timeout=2s --retries=5 CMD python -c "import urllib.request,sys;sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:9100/health').status==200 else 1)"
CMD ["python", "-m", "pdp.server"]
