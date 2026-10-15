# One image, three programs: reversi-server (default), reversi-gateway, reversi (CLI).
#   docker run ... reversi                                   # server
#   docker run ... reversi node packages/gateway/dist/main.js --config /config/gateway.yaml --manifests /config/manifests
FROM node:22-slim AS build
WORKDIR /app
COPY package.json package-lock.json tsconfig.base.json tsconfig.json ./
COPY packages ./packages
RUN npm ci && npx tsc -b && npm prune --omit=dev

FROM node:22-slim
ENV NODE_ENV=production REVERSI_DATA=/data HOST=0.0.0.0 PORT=7421
WORKDIR /app
COPY --from=build /app/package.json ./
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/packages ./packages
RUN mkdir /data && chown node:node /data
USER node
VOLUME /data
EXPOSE 7421
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||7421)+'/readyz').then(r=>process.exit(r.ok?0:1),()=>process.exit(1))"
CMD ["node", "packages/server/dist/main.js"]
