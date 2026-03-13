FROM python:3.12-slim-bookworm

WORKDIR /usr/src/vulnhuntr
COPY . .
RUN pip install --no-cache-dir .

ENTRYPOINT [ "vulnhuntr" ]
