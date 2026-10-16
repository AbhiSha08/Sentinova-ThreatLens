# ==============================================================================
# Sentinova ThreatLens Frontend Dockerfile (Multi-stage Production Build)
# Stage 1: Build React 18 + Vite production bundle
# Stage 2: Serve optimized static assets via Nginx Alpine reverse proxy
# ==============================================================================

# ── Stage 1: Build ────────────────────────────────────────────────────────────
FROM node:20-alpine AS builder

WORKDIR /app

# Copy dependency specifications and install cleanly
COPY package.json package-lock.json* ./
RUN npm install

# Copy source code and build production bundle
COPY . .
RUN npm run build

# ── Stage 2: Production Nginx Server ──────────────────────────────────────────
FROM nginx:alpine

# Copy custom Nginx configuration with reverse proxy for /api/
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Copy compiled static assets from builder stage
COPY --from=builder /app/dist /usr/share/nginx/html

# Expose HTTP port
EXPOSE 80

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget -q --spider http://localhost:80 || exit 1

CMD ["nginx", "-g", "daemon off;"]
