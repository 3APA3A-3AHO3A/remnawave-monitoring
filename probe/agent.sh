#!/bin/sh
# Связь пробы с сервером мониторинга (контейнер agent, см. docker-compose.yml).
# Раз в минуту:
#   1. берёт список хостов для проверки (/ru/hosts.json) и, если он изменился,
#      кладёт его для xray-checker (/links/ru-hosts.json);
#   2. отправляет результаты xray-checker (/ru/metrics).
# Сертификат мониторинга самоподписанный: проверяется его ключ (MON_PIN), запомненный
# при установке, поэтому подменить сервер мониторинга нельзя.
set -u
apk add --no-cache curl >/dev/null 2>&1 || true
PASS=$(cat /secret/password)
LIST=/links/ru-hosts.json
# пока списка нет — заглушка: xray-checker с пустым списком не запускается
[ -s "$LIST" ] || printf '%s\n' '[{"remarks":"rwmon-empty","outbounds":[{"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":"127.0.0.1","port":9,"users":[{"id":"00000000-0000-0000-0000-000000000000","encryption":"none"}]}]}}]}]' > "$LIST"

mon() {   # запрос к мониторингу: путь, дальше — параметры curl
  path=$1; shift
  curl -sS --fail --max-time 30 -k --pinnedpubkey "$MON_PIN" -u "rwmon:$PASS" "$@" "$MON_URL$path"
}

last_err=""
say() {   # одна и та же ошибка — в журнал один раз
  [ "$1" = "$last_err" ] && return
  last_err=$1
  echo "$(date -u '+%F %T') $1"
}

while :; do
  if mon /ru/hosts.json -o "$LIST.tmp" 2>/tmp/err; then
    if ! cmp -s "$LIST.tmp" "$LIST"; then
      mv "$LIST.tmp" "$LIST"
      echo "$(date -u '+%F %T') список хостов обновлён"
    fi
    ok=1
  else
    say "мониторинг не отдал список: $(cat /tmp/err)"
    ok=0
  fi
  if curl -s --fail --max-time 10 -o /tmp/metrics "$CHECKER_METRICS"; then
    if mon /ru/metrics --data-binary @/tmp/metrics -H 'Content-Type: text/plain' 2>/tmp/err; then
      [ $ok = 1 ] && say "работает"
    else
      say "результаты не отправлены: $(cat /tmp/err)"
    fi
  else
    say "xray-checker ещё не отдаёт результаты (запускается)"
  fi
  sleep 60
done
