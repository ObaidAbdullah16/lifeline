# Small, non-root image: docker run --rm ghcr.io/obaidabdullah16/lifeline scan --repo owner/name
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/lifeline ./cmd/lifeline

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/lifeline /lifeline
USER nonroot:nonroot
ENTRYPOINT ["/lifeline"]
