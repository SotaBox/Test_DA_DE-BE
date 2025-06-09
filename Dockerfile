FROM golang:1.21-alpine AS builder
LABEL authors="admin"

WORKDIR /app
COPY . .
# download all dependencies
RUN go mod download

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /app/main .

FROM alpine:latest

COPY --from=builder /app/main /app/main
WORKDIR /app
EXPOSE 8080
CMD ["/app/main"]