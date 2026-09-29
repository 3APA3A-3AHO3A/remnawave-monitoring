# xray-checker v1.3.1 с двумя патчами: Hysteria2 + Salamander packetSize и повторные попытки.
#
# Официальный xray-checker теряет параметр packetSize у обфускации Salamander.
# С packetSize ядро Xray работает в режиме Gecko, который несовместим с обычным
# Salamander, и сервер молча отбрасывает пакеты проверки (ошибка EOF).
# Патч маленький: packetSize берётся из параметра fm ссылки и передаётся в Xray.
#
# check-retries.patch: одна неудачная попытка (например, EOF от WARP после простоя)
# больше не считается сбоем — проверка повторяется PROXY_CHECK_ATTEMPTS раз
# с паузой PROXY_CHECK_RETRY_DELAY секунд.
#
# Когда исправления появятся в самом xray-checker, этот файл можно удалить
# и вернуть в docker-compose.yml готовый образ kutovoys/xray-checker.

FROM golang:1.26-alpine AS builder
ARG XC_VERSION=v1.3.1
ENV CGO_ENABLED=0 GO111MODULE=on
RUN apk add --no-cache git patch
RUN git clone --depth 1 --branch ${XC_VERSION} https://github.com/kutovoys/xray-checker /src
WORKDIR /src
COPY *.patch /tmp/patches/
RUN for p in /tmp/patches/*.patch; do patch -p1 < "$p" || exit 1; done && go mod download
RUN go build -ldflags="-s -w -X main.version=${XC_VERSION}-rwmon" -o /usr/bin/xray-checker .

FROM alpine:3.21
RUN apk add --no-cache ca-certificates tzdata && \
    adduser -D -u 1000 appuser && \
    mkdir -p /app/geo && chown -R appuser:appuser /app
WORKDIR /app
COPY --from=builder /usr/bin/xray-checker /usr/bin/xray-checker
USER appuser
ENTRYPOINT ["/usr/bin/xray-checker"]
