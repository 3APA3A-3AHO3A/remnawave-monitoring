#!/bin/sh
# Запускает xray-checker на каждую проверку: /etc/rwmon/checkers/<id>.env (их собирает
# контейнер config из config.toml). Строки журнала помечаются [id проверки].
# Упал один процесс — останавливаются все, и docker перезапускает контейнер целиком.
set -u
DIR=/etc/rwmon/checkers
set -- "$DIR"/*.env
[ -e "$1" ] || { echo "нет файлов проверок в $DIR — контейнер config не отработал?"; exit 1; }
pids=""
for f in "$@"; do
  id=$(basename "$f" .env)
  # shellcheck disable=SC1090  # файл проверки — по переменной
  ( set -a; . "$f"; set +a
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
