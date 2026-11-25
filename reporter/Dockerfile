FROM python:3.15-alpine

# Только стандартная библиотека Python — pip не нужен, его убираем вместе с уязвимостями,
# которые в нём находит сканер образов; системные пакеты Alpine — до свежих исправлений;
# tzdata — часовые пояса для тихих часов бота.
# Работает от root внутри контейнера: так он может читать config.toml
# с правами 600 и писать в общие тома; наружу ничего не открывает.
RUN apk upgrade --no-cache && apk add --no-cache tzdata && pip uninstall -y pip && \
    rm -rf /usr/local/lib/python3*/ensurepip /root/.cache
WORKDIR /app
COPY rwmon ./rwmon
ENV PYTHONUNBUFFERED=1 TZ=UTC

ENTRYPOINT ["python", "-m", "rwmon"]
CMD ["run"]
