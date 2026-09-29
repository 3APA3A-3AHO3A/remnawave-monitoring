#!/bin/sh
# Установка пробы из РФ на RU-ноду.
#   ./install.sh <IP сервера мониторинга> [порт, по умолчанию 9115]
# Делает: самоподписанный сертификат, случайный пароль, web.yml, правило файрвола (ufw),
# запускает контейнер и печатает блок для config.toml мониторинга.
set -e
cd "$(dirname "$0")"
MON_IP="$1"
PORT="${2:-9115}"
[ -n "$MON_IP" ] || { echo "Укажите IP сервера мониторинга: ./install.sh 1.2.3.4"; exit 1; }
command -v docker >/dev/null || { echo "Нужен Docker"; exit 1; }

mkdir -p secret
chmod 700 secret
if [ ! -f secret/tls.key ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=rwmon-probe" \
    -keyout secret/tls.key -out secret/tls.crt 2>/dev/null
fi
if [ ! -f secret/password ]; then
  openssl rand -hex 24 > secret/password
fi
chmod 600 secret/tls.key secret/password
PASS="$(cat secret/password)"
HASH="$(docker run --rm httpd:2.4-alpine htpasswd -nbB rwmon "$PASS" | cut -d: -f2)"

cat > web.yml <<YML
tls_server_config:
  cert_file: /etc/blackbox/secret/tls.crt
  key_file: /etc/blackbox/secret/tls.key
basic_auth_users:
  rwmon: '$HASH'
YML

echo "PROBE_PORT=$PORT" > .env
docker compose up -d

if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
  ufw allow from "$MON_IP" to any port "$PORT" proto tcp comment 'rwmon probe'
  echo "ufw: порт $PORT открыт только для $MON_IP"
else
  echo "ВНИМАНИЕ: ufw не активен. Откройте порт $PORT только для $MON_IP в своём файрволе."
fi

IP="$(curl -4 -s --max-time 5 https://icanhazip.com || hostname -I | cut -d' ' -f1)"
cat <<TOML

Готово. Добавьте в config.toml мониторинга и выполните ./apply.sh:

[[probe]]
name = "ru-$(hostname -s | tr 'A-Z' 'a-z' | tr -cd 'a-z0-9-' | cut -c1-20)"
url = "https://$IP:$PORT"
user = "rwmon"
password = "$PASS"
TOML
