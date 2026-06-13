# Veritrace image. Builds the console, then a slim Python runtime that serves
# both the API (veritrace serve) and the MCP server (veritrace mcp-server).

# ---- stage 1: build the console ----
FROM node:20-alpine AS console
WORKDIR /console
COPY console/package.json console/package-lock.json* ./
RUN npm install
COPY console/ ./
RUN npm run build

# ---- stage 2: python runtime ----
FROM python:3.12-slim AS runtime
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app

COPY pyproject.toml README.md ./
COPY veritrace ./veritrace
RUN pip install --upgrade pip && pip install .

COPY --from=console /console/dist ./console/dist

EXPOSE 8400 8052
CMD ["veritrace", "serve"]
