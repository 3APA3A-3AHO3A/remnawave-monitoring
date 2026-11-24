# xray-checker v1.3.1 с четырьмя патчами: Hysteria2 + Salamander packetSize, повторные попытки,
# IP выхода и причина сбоя в метриках, подключение через посредника.
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
# rwmon-metrics.patch: две метрики для алертов.
#   xray_proxy_exit_ip{..., ip="…"} — с какого IP проверка вышла в интернет. Если это
#   IP одной из наших нод, запрос ушёл напрямую, мимо WARP или Psiphon: по одному
#   «IP отличается от IP сервера проверки» этого не видно.
#   xray_proxy_error_code — причина сбоя числом (таймаут, обрыв, отказ, TLS, DNS…),
#   её алерт пишет в сообщении. Числа — в checker/errcode.go патча и в render.py.
#
# rwmon-via.patch: аутбаунд с тегом rwmon-via в JSON-конфиге хоста — посредник:
#   остальные аутбаунды конфига подключаются через него (sockopt.dialerProxy),
#   сам он отдельно не проверяется. Так работает проверка «Клиент из РФ».
#
# Когда исправления появятся в самом xray-checker, этот файл можно удалить
# и вернуть в docker-compose.yml готовый образ kutovoys/xray-checker.

FROM golang:1.27-alpine AS builder
ARG XC_VERSION=v1.3.1
ENV CGO_ENABLED=0 GO111MODULE=on
RUN apk add --no-cache git patch
RUN git clone --depth 1 --branch ${XC_VERSION} https://github.com/kutovoys/xray-checker /src
WORKDIR /src
COPY *.patch /tmp/patches/
RUN for p in /tmp/patches/*.patch; do patch -p1 < "$p" || exit 1; done && go mod download
RUN go build -ldflags="-s -w -X main.version=${XC_VERSION}-rwmon" -o /usr/bin/xray-checker .

FROM alpine:3.24
RUN apk add --no-cache ca-certificates tzdata && \
    adduser -D -u 1000 appuser && \
    mkdir -p /app/geo && chown -R appuser:appuser /app
WORKDIR /app
COPY --from=builder /usr/bin/xray-checker /usr/bin/xray-checker
# все проверки из config.toml — процессами в одном контейнере (см. run-all.sh)
COPY run-all.sh /usr/bin/rwmon-checkers
USER appuser
ENTRYPOINT ["/usr/bin/rwmon-checkers"]
