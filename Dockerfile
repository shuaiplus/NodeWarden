FROM node:24-alpine AS builder

WORKDIR /app

RUN apk add --no-cache python3 make g++

COPY package*.json ./
RUN npm ci

COPY . .

RUN npm run build:local

RUN npm prune --omit=dev

FROM node:24-alpine

WORKDIR /app

RUN apk add --no-cache python3

COPY --from=builder /app/package*.json ./
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/dist ./dist

RUN mv ./dist/server.cjs ./server.cjs

EXPOSE 8787

ENV PORT=8787
ENV DB_PATH=/nodewarden/db.sqlite
ENV LOCAL_ATTACHMENTS_DIR=/nodewarden/attachments

CMD ["node", "server.cjs"]
