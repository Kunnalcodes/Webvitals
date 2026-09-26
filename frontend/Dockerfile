# Multi-stage Dockerfile for Vite React Frontend
# Stage 1: Build the production bundle
FROM node:20-alpine AS builder

WORKDIR /app

# Copy package descriptors and install dependencies
COPY package*.json ./
RUN npm ci || npm install

# Copy frontend source code and build
COPY . .
RUN npm run build

# Stage 2: Serve static files with lightweight Nginx Alpine
FROM nginx:alpine AS runner

# Copy built static assets from builder stage
COPY --from=builder /app/dist /usr/share/nginx/html

# Copy custom Nginx configuration with reverse proxy for /api/
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Expose HTTP port
EXPOSE 80

# Run nginx in foreground
CMD ["nginx", "-g", "daemon off;"]
