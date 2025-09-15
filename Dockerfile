FROM golang:alpine AS build

COPY . /src/

WORKDIR /src

RUN CGO_ENABLED=0 go build -ldflags="-s -w" -trimpath -o usit .

FROM alpine:latest

COPY --from=build /src/usit /usr/local/bin/usit
COPY entrypoint.sh /entrypoint.sh

CMD ["/entrypoint.sh"]
