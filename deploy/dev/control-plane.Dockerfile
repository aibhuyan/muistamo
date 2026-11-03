# Development image for `control-plane gateway authz` in the dev stack's gateway profile
# (make dev-gateway). Not a production image: production transport is not integrated.
FROM golang:1.27 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY contracts/ contracts/
COPY control-plane/ control-plane/
RUN CGO_ENABLED=0 go build -trimpath -o /out/control-plane ./control-plane/cmd/control-plane
# Never an end-to-end build: only those can send Entra and Graph traffic to a fake.
RUN if go version -m /out/control-plane | grep -q -- '-tags=.*e2e'; then echo "e2e build refused" >&2; exit 1; fi

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/control-plane /control-plane
ENTRYPOINT ["/control-plane"]
