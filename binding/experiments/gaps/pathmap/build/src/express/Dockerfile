FROM node:24.22.3-alpine3.24
ENV NODE_ENV=production FRAMEWORK_TAG=express OVERRIDE=off VERIFY_MODE=off
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund
COPY app.js viewmac.js ./
RUN mkdir -p /logs
EXPOSE 8080
CMD ["node", "app.js"]

# W15 ext-routes: ROUTES=v2 enables the richer v1 route space (build :v2 with --build-arg ROUTES=v2).
ARG ROUTES=off
ENV ROUTES=${ROUTES}
