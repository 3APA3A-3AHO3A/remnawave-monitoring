# xray-checker с исправлением для Hysteria2 + Salamander packetSize.
#
# Официальный xray-checker теряет параметр packetSize у обфускации Salamander.
# С packetSize ядро Xray работает в режиме Gecko, который несовместим с обычным
# Salamander, и сервер молча отбрасывает пакеты проверки (ошибка EOF).
# Патч маленький: packetSize берётся из параметра fm ссылки и передаётся в Xray.
# Когда исправление появится в самом xray-checker, этот файл можно удалить
# и вернуть в docker-compose.yml готовый образ kutovoys/xray-checker.

FROM golang:1.26-alpine AS builder
ARG XC_VERSION=v1.3.1
ENV CGO_ENABLED=0 GO111MODULE=on
RUN apk add --no-cache git patch
RUN git clone --depth 1 --branch ${XC_VERSION} https://github.com/kutovoys/xray-checker /src
WORKDIR /src
COPY hysteria-salamander-packetsize.patch /tmp/
RUN patch -p1 < /tmp/hysteria-salamander-packetsize.patch && go mod download
RUN go build -ldflags="-s -w -X main.version=${XC_VERSION}-rwmon" -o /usr/bin/xray-checker .

FROM alpine:3.21
RUN apk add --no-cache ca-certificates tzdata && \
    adduser -D -u 1000 appuser && \
    mkdir -p /app/geo && chown -R appuser:appuser /app
WORKDIR /app
COPY --from=builder /usr/bin/xray-checker /usr/bin/xray-checker
USER appuser
ENTRYPOINT ["/usr/bin/xray-checker"]
