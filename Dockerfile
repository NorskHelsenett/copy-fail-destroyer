FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /destroyer ./cmd/destroyer

FROM scratch
COPY --from=build /destroyer /destroyer
ENTRYPOINT ["/destroyer"]
