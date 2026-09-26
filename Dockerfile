# ==============================================================================
# WebVitals — Production Dockerfile
# Full-Stack Web Security, SEO & Tech Stack Intelligence Platform
# Multi-stage build: Frontend Vite builder + Zero-Dependency Node.js runner
# ==============================================================================

# --- Stage 1: Build Frontend ---
FROM node:20-alpine AS frontend-builder
WORKDIR /app/frontend

COPY frontend/package*.json ./
RUN npm ci || npm install

COPY frontend/ ./
RUN npm run build

# --- Stage 2: Production Server ---
FROM node:20-alpine AS runner
WORKDIR /app

ENV NODE_ENV=production
ENV PORT=8888

# Copy root & backend package files
COPY package*.json ./
COPY backend/package*.json ./backend/

# Copy backend code
COPY backend/ ./backend/
COPY scripts/ ./scripts/

# Copy compiled frontend dist from Stage 1
COPY --from=frontend-builder /app/frontend/dist ./frontend/dist

# Expose production port
EXPOSE 8888

# Healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD node -e "require('http').get('http://localhost:' + (process.env.PORT || 8888) + '/api/health', (r) => { process.exit(r.statusCode === 200 ? 0 : 1); }).on('error', () => process.exit(1));"

# Run as non-root user for container security
USER node

# Start Unified Full-Stack Server
CMD ["node", "backend/index.js"]
