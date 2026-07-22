FROM python:3.12-alpine

WORKDIR /app

COPY serve.py index.html cover.jpg robots.txt sitemap.xml README.md README.ru.md DISCLAIMER.md ./
COPY app/ app/
COPY css/ css/
COPY data/cves_public.json data/cves_public.provenance.json data/
COPY education/ education/
COPY image/ image/
COPY js/ js/
COPY offline-cve/ offline-cve/
COPY owasp-labs/ owasp-labs/
COPY ru/ ru/
COPY source/ source/

ENV ROOT_HOST=0.0.0.0 \
    ROOT_PORT=8080 \
    ROOT_DB_PATH=/tmp/root-cves.sqlite3

EXPOSE 8080

USER nobody

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s \
  CMD wget -qO- http://127.0.0.1:8080/api/health >/dev/null || exit 1

CMD ["python3", "serve.py"]
