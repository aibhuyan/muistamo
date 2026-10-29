# Development image for `control-plane gateway authz` in the dev stack's gateway profile
# (make dev-gateway). Not a production image: production transport is not integrated.
FROM golang:1.27 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY contracts/ contracts/
COPY control-plane/ control-plane/
RUN CGO_ENABLED=0 go build -trimpath -o /out/control-plane ./control-plane/cmd/control-plane

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/control-plane /control-plane
ENTRYPOINT ["/control-plane"]
