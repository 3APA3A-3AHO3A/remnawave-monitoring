FROM python:3.13-alpine

# Только стандартная библиотека Python — pip ничего не ставит.
# Работает от root внутри контейнера: так он может читать config.toml
# с правами 600 и писать в общие тома; наружу ничего не открывает.
WORKDIR /app
COPY rwmon ./rwmon
ENV PYTHONUNBUFFERED=1 TZ=UTC

ENTRYPOINT ["python", "-m", "rwmon"]
CMD ["run"]
