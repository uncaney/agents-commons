# Backup sidecar: pg_dump (same major as the server) + GNU tar + age, nothing else.
FROM postgres:17-alpine
RUN apk add --no-cache age tar
COPY backup.sh /usr/local/bin/backup.sh
RUN chmod 0555 /usr/local/bin/backup.sh
ENTRYPOINT ["/usr/local/bin/backup.sh"]
