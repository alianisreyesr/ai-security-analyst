FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY pyproject.toml ./
COPY app ./app
COPY alembic ./alembic
COPY alembic.ini ./

RUN python -m pip install --no-cache-dir --upgrade \
      "pip>=26" \
      "setuptools>=78.1.1" \
      "msgpack>=1.2.1" \
    && python -m pip install --no-cache-dir . \
    && rm -rf \
      /usr/local/lib/python3.12/site-packages/setuptools-70.3.0.dist-info \
      /usr/local/lib/python3.12/site-packages/msgpack-1.1.2.dist-info \
    && python -c "from importlib.metadata import version; \
assert tuple(map(int, version('msgpack').split('.')[:3])) >= (1, 2, 1); \
assert tuple(map(int, version('setuptools').split('.')[:2])) >= (78, 1)"

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
