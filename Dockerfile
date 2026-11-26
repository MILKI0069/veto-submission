# Veto, deployable image. The Playwright base image ships a matching Chromium for the X-ray chamber.
# Production hardening (recommended): run with a read-only root FS, no extra capabilities, an egress-only
# network policy that blocks private ranges, and recycle the container regularly.
FROM mcr.microsoft.com/playwright:v1.65.1-noble

WORKDIR /app
ENV NODE_ENV=production PORT=8787 VETO_DEMO=1
COPY package.json package-lock.json* ./
RUN npm ci --omit=dev || npm install --omit=dev
COPY . .
RUN mkdir -p /app/var && chown -R pwuser:pwuser /app/var
USER pwuser
EXPOSE 8787
CMD ["node", "server/server.js"]
