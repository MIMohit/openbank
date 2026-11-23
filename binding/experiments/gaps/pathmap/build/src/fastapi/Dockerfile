FROM python:3.12.16-slim-trixie
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 FRAMEWORK_TAG=fastapi OVERRIDE=off VERIFY_MODE=off
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py viewmac.py ./
RUN mkdir -p /logs
EXPOSE 8080
# plain uvicorn (h11 / httptools auto-selected; httptools not installed -> h11), no proxy-headers rewriting
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080", "--no-proxy-headers", "--no-server-header", "--log-level", "warning"]

# W15 ext-routes: ROUTES=v2 enables the richer v1 route space (build :v2 with --build-arg ROUTES=v2).
ARG ROUTES=off
ENV ROUTES=${ROUTES}
