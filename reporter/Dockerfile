FROM python:3.13-alpine

# Только стандартная библиотека Python — pip ничего не ставит
RUN adduser -D -u 10001 app && mkdir -p /data /links && chown app:app /data /links

WORKDIR /app
COPY rwmon ./rwmon
USER app
ENV PYTHONUNBUFFERED=1 TZ=UTC

ENTRYPOINT ["python", "-m", "rwmon"]
CMD ["run"]
