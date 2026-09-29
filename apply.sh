#!/bin/sh
# Применить изменения config.toml или обновление из git:
# собрать образы, пересобрать конфиги и перезапустить все контейнеры.
# Данные Prometheus и Grafana при этом сохраняются.
set -e
cd "$(dirname "$0")"
[ -f config.toml ] || { echo "Нет config.toml — см. README, раздел «Установка»"; exit 1; }
docker compose build
if ! docker compose up -d --force-recreate --remove-orphans; then
  echo
  echo "Не запустилось. Сообщение контейнера config (обычно — ошибка в config.toml):"
  docker compose logs --no-log-prefix --tail 20 config
  exit 1
fi
# после пересборки старые версии наших образов остаются без имени — убираем только их
docker image prune -f --filter label=rwmon >/dev/null || true
sleep 5
docker compose ps -a
echo
echo "Проверка (через минуту): docker compose exec reporter python -m rwmon check"
