# Multi-stage: `dev` for the compose dev overlay, `runner` for the reference
# deployment. Node base is digest-pinned for the same reason the Python one is.
FROM node:22-slim AS deps
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci || npm install

FROM node:22-slim AS dev
WORKDIR /app
ENV NEXT_TELEMETRY_DISABLED=1
COPY --from=deps /app/node_modules ./node_modules
COPY . .
EXPOSE 3000
CMD ["npm", "run", "dev"]

FROM node:22-slim AS builder
WORKDIR /app
ENV NEXT_TELEMETRY_DISABLED=1
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN npm run build

FROM node:22-slim AS runner
WORKDIR /app
ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    PORT=3000 \
    HOSTNAME=0.0.0.0

RUN groupadd --gid 10002 nextjs \
 && useradd --uid 10002 --gid 10002 --create-home --shell /usr/sbin/nologin nextjs

COPY --from=builder --chown=nextjs:nextjs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nextjs /app/.next/static ./.next/static
COPY --from=builder --chown=nextjs:nextjs /app/public ./public

# Where the setup wizard persists the minted API token (BARE_TOKEN_FILE
# in web/lib/runtime-token.ts). Owned by the app user *before* the named
# volume in docker-compose.yml mounts over it: unlike a tmpfs or bind mount, a
# named volume's first mount copies in whatever ownership the image already
# has at that path — so this has to be set here, not fixed up at runtime by a
# non-root process that cannot chown its own mount point.
RUN mkdir -p /app/data && chown nextjs:nextjs /app/data

USER 10002:10002
EXPOSE 3000
CMD ["node", "server.js"]
