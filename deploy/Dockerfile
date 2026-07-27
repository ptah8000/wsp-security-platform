# syntax=docker/dockerfile:1

# -----------------------------------------------------------------------------
# Stage 1: build admin UI (Vite React + Tailwind → web/dist)
# -----------------------------------------------------------------------------
FROM node:20-alpine AS ui
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

# -----------------------------------------------------------------------------
# Stage 2: build Go binary (CGO disabled, embed UI from web/dist)
# -----------------------------------------------------------------------------
FROM golang:1.25-alpine AS build
WORKDIR /src

RUN apk add --no-cache ca-certificates git

COPY go.mod ./
# go.sum may be absent while the module has no external deps
COPY go.sum* ./
RUN go mod download 2>/dev/null || true

COPY . .
COPY --from=ui /src/web/dist ./web/dist

ENV CGO_ENABLED=0
ENV GOOS=linux
ENV GOTOOLCHAIN=auto
RUN go build -trimpath -ldflags="-s -w" -o /out/wsp ./cmd/wsp

# -----------------------------------------------------------------------------
# Stage 3: minimal runtime (RBI uses Docker API; Chromium is not in this image)
# -----------------------------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/wsp /wsp
EXPOSE 8080 3000
USER nonroot:nonroot
ENTRYPOINT ["/wsp"]
