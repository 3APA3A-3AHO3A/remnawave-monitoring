#!/bin/sh
# Запускает xray-checker на каждую проверку: /etc/rwmon/checkers/<id>.env (их собирает
# контейнер config из config.toml). Строки журнала помечаются [id проверки].
# Упал один процесс — останавливаются все, и docker перезапускает контейнер целиком.
#
# У каждой проверки своя рабочая папка /app/run/<id>: xray-checker пишет конфиг Xray
# в ./xray_config.json и перечитывает его при смене подписки. В общей папке проверки
# перезаписывали один файл друг другу: одна читала его недописанным (EOF) и оставалась
# без Xray, а при старте могла запустить Xray с чужим конфигом.
# geo-базы общие (/app/geo): их скачиваем здесь один раз, до запуска проверок, чтобы
# процессы не качали один файл одновременно.
set -u
DIR=/etc/rwmon/checkers
GEO=/app/geo
set -- "$DIR"/*.env
[ -e "$1" ] || { echo "нет файлов проверок в $DIR — контейнер config не отработал?"; exit 1; }

geo_fetch() {   # $1 — файл в $GEO, $2 — ссылка; через временный файл, чтобы не оставить обрывок
  [ -s "$GEO/$1" ] && return 0
  if wget -q -T 60 -O "$GEO/.$1.tmp" "$2" && [ -s "$GEO/.$1.tmp" ]; then
    mv "$GEO/.$1.tmp" "$GEO/$1"
  else
    rm -f "$GEO/.$1.tmp"
    echo "не скачался $1 — xray-checker попробует сам"
  fi
}
mkdir -p "$GEO"
geo_fetch geosite.dat https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat
geo_fetch geoip.dat https://github.com/v2fly/geoip/releases/latest/download/geoip.dat

pids=""
for f in "$@"; do
  id=$(basename "$f" .env)
  work="/app/run/$id"
  mkdir -p "$work" && ln -sfn "$GEO" "$work/geo"
  # shellcheck disable=SC1090  # файл проверки — по переменной
  ( cd "$work" || exit 1
    set -a; . "$f"; set +a
    # построчно силами sh: awk копит ввод блоками, и строки появлялись бы с задержкой
    /usr/bin/xray-checker 2>&1 | while IFS= read -r line; do echo "[$id] $line"; done ) &
  pids="$pids $!"
  echo "[$id] запущена проверка (порт метрик $(sed -n "s/^METRICS_PORT='\(.*\)'$/\1/p" "$f"))"
done
trap 'trap - TERM INT; kill 0; exit 0' TERM INT
while :; do
  for p in $pids; do
    if ! kill -0 "$p" 2>/dev/null; then
      echo "одна из проверок завершилась — перезапуск контейнера"
      trap - TERM INT; kill 0; exit 1
    fi
  done
  sleep 5
done
