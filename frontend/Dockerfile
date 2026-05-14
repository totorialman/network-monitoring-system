# Frontend Dockerfile for Network Monitor SOC Dashboard
# Builds React/Vite UI and serves it through Nginx with SSL + same-origin /api proxy to Go backend.
FROM node:22-alpine AS builder

WORKDIR /app
RUN corepack enable
COPY package.json pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile
COPY client ./client
COPY shared ./shared
COPY tsconfig.json vite.config.ts ./
ARG VITE_API_BASE_URL=
ENV VITE_API_BASE_URL=${VITE_API_BASE_URL}
RUN pnpm run build

FROM nginx:1.27-alpine

# Устанавливаем curl для healthcheck
RUN apk add --no-cache curl

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=builder /app/dist/public /usr/share/nginx/html
EXPOSE 80 443
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD curl -f http://localhost:80/healthz || exit 1
CMD ["nginx", "-g", "daemon off;"]