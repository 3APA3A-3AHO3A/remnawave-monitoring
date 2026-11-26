#!/bin/sh
# Установка и обновление пробы из РФ.
#   ./install.sh <IP сервера мониторинга> [порт пробы, по умолчанию 9115] [порт мониторинга, по умолчанию 9116]
# Делает:
#   - самоподписанный сертификат и пароль пробы (один раз; при обновлении остаются прежними);
#   - запоминает ключ сертификата сервера мониторинга (связь только с ним);
#   - закрепляет порты проверок Xray, открывает порт пробы для IP мониторинга (ufw);
#   - скачивает образ проверки (или собирает его здесь), запускает контейнеры;
#   - печатает блок [[probe]] для config.toml мониторинга.
# На сервере мониторинга порт 9116 должен быть открыт для IP этой пробы — иначе ключ не получить.
set -e
cd "$(dirname "$0")"
MON_IP="$1"
PORT="${2:-9115}"
MON_PORT="${3:-9116}"
XRAY_PORT=41000
[ -n "$MON_IP" ] || { echo "Укажите IP сервера мониторинга: ./install.sh 1.2.3.4"; exit 1; }
command -v docker >/dev/null || { echo "Нужен Docker"; exit 1; }
command -v openssl >/dev/null || { echo "Нужен openssl: sudo apt install -y openssl"; exit 1; }

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

# ключ сертификата мониторинга: запоминаем при первой установке, дальше сверяем
PIN_NOW="$(echo | timeout 10 openssl s_client -connect "$MON_IP:$MON_PORT" 2>/dev/null \
  | openssl x509 -pubkey -noout 2>/dev/null | openssl pkey -pubin -outform der 2>/dev/null \
  | openssl dgst -sha256 -binary | openssl base64 -A)"
OLD_PIN="$(sed -n 's/^MON_PIN=//p' .env 2>/dev/null || true)"
if [ -z "$PIN_NOW" ] || [ "$PIN_NOW" = "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=" ]; then
  if [ -n "$OLD_PIN" ]; then
    echo "Мониторинг $MON_IP:$MON_PORT сейчас не отвечает — оставляю прежний ключ"
    PIN="$OLD_PIN"
  else
    echo "Не удалось получить ключ сертификата мониторинга с $MON_IP:$MON_PORT."
    echo "Откройте на сервере мониторинга порт $MON_PORT для IP этой пробы и повторите:"
    echo "  sudo ufw allow from <IP пробы> to any port $MON_PORT proto tcp comment 'rwmon probe'"
    exit 1
  fi
else
  PIN="sha256//$PIN_NOW"
  if [ -n "$OLD_PIN" ] && [ "$OLD_PIN" != "$PIN" ]; then
    echo "ВНИМАНИЕ: ключ сертификата мониторинга изменился ($OLD_PIN → $PIN)."
    echo "Если вы не переустанавливали мониторинг — не продолжайте. Сверьте с выводом"
    echo "  docker compose exec reporter python -m rwmon check   (строка «сертификат»)"
    printf "Принять новый ключ? [y/N] "
    read -r ans
    [ "$ans" = "y" ] || exit 1
  fi
fi

cat > .env <<ENV
PROBE_PORT=$PORT
MON_URL=https://$MON_IP:$MON_PORT
MON_PIN=$PIN
CHECKER_XRAY_PORT=$XRAY_PORT
ENV

# порты Xray проверок не должны достаться исходящим соединениям
RESERVED="$XRAY_PORT-$((XRAY_PORT + 999))"
if ! grep -qs "$RESERVED" /etc/sysctl.d/90-rwmon-probe.conf; then
  echo "net.ipv4.ip_local_reserved_ports = $RESERVED" > /etc/sysctl.d/90-rwmon-probe.conf
  sysctl -q -p /etc/sysctl.d/90-rwmon-probe.conf
  echo "порты проверок $RESERVED закреплены"
fi

if docker compose pull -q checker 2>/dev/null; then
  echo "образ проверки скачан"
else
  echo "готового образа нет — собираю проверку здесь (несколько минут)"
  docker compose build checker
fi
docker compose up -d --remove-orphans
docker image prune -f --filter label=rwmon >/dev/null 2>&1 || true

if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
  ufw allow from "$MON_IP" to any port "$PORT" proto tcp comment 'rwmon probe' >/dev/null
  echo "ufw: порт $PORT открыт только для $MON_IP"
else
  echo "ВНИМАНИЕ: ufw не активен. Откройте порт $PORT только для $MON_IP в своём файрволе."
fi

IP="$(curl -4 -s --max-time 5 https://icanhazip.com || hostname -I | cut -d' ' -f1)"
cat <<TOML

Готово. Ключ сертификата мониторинга: $PIN
Если пробы ещё нет в config.toml мониторинга — добавьте блок и выполните там ./apply.sh:

[[probe]]
name = "ru-$(hostname -s | tr 'A-Z' 'a-z' | tr -cd 'a-z0-9-' | cut -c1-20)"
url = "https://$IP:$PORT"
user = "rwmon"
password = "$PASS"

Журнал связи с мониторингом: docker compose logs -f agent
TOML
