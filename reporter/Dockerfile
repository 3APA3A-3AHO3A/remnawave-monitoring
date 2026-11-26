FROM python:3.15-alpine

# Только стандартная библиотека Python — pip не нужен, его убираем вместе с уязвимостями,
# которые в нём находит сканер образов; системные пакеты Alpine — до свежих исправлений;
# tzdata — часовые пояса для тихих часов бота; openssl — сертификат для проб из РФ (feed.py).
# Работает от root внутри контейнера: так он может читать config.toml
# с правами 600 и писать в общие тома. Наружу открыт только порт для проб из РФ
# ([checks] ru_port, HTTPS с паролем пробы), и только если в config.toml есть [[probe]].
RUN apk upgrade --no-cache && apk add --no-cache tzdata openssl && pip uninstall -y pip && \
    rm -rf /usr/local/lib/python3*/ensurepip /root/.cache
WORKDIR /app
COPY rwmon ./rwmon
ENV PYTHONUNBUFFERED=1 TZ=UTC

ENTRYPOINT ["python", "-m", "rwmon"]
CMD ["run"]
