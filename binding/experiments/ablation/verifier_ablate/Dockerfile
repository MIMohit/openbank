# W18 ablation verifier. Build from experiments/ablation/verifier_ablate:
#   docker build -t bh-verifier:ablate .
# Variant tags are thin layers that only set BIND_CLAIMS / QUERY_CANON (scripts/build_images.sh).
FROM python:3.12.8-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PORT=9100 LOG_PATH=/logs/verifier.jsonl \
    AS_PUB_JWK=/app/keys/as_pub.jwk HTU_CANON=rfc3986 JTI_CACHE=on IAT_WINDOW=60 VIEW_MAC=off \
    BIND_CLAIMS=full QUERY_CANON=rfc3986
WORKDIR /app
COPY requirements.txt /app/verifier/requirements.txt
RUN pip install --no-cache-dir -r /app/verifier/requirements.txt
COPY __init__.py core.py canon.py jose.py server.py bind.py digest_gate.py /app/verifier/
COPY as_pub.jwk /app/keys/as_pub.jwk
RUN useradd -r -u 10001 verifier && mkdir -p /logs && chown verifier /logs
USER verifier
EXPOSE 9100
HEALTHCHECK --interval=5s --timeout=2s --retries=5 CMD python -c "import urllib.request,sys;sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:9100/health').status==200 else 1)"
CMD ["python", "-m", "verifier.server"]
