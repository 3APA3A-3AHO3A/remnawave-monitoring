#!/bin/sh
# Применить изменения config.toml или обновление из git:
# собрать образы, пересобрать конфиги и перезапустить все контейнеры.
# Данные Prometheus и Grafana при этом сохраняются.
set -e
cd "$(dirname "$0")"
[ -f config.toml ] || { echo "Нет config.toml — см. README, раздел «Установка»"; exit 1; }
docker compose build
docker compose up -d --force-recreate --remove-orphans
# после пересборки старые версии образов остаются без имени и никем не используются — убираем их
docker image prune -f >/dev/null || true
sleep 5
docker compose ps -a
echo
echo "Проверка (через минуту): docker compose exec reporter python -m rwmon check"
