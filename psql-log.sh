#!/bin/bash

CONF=$(find /etc/postgresql -name postgresql.conf 2>/dev/null | head -n 1)

echo "log_statement = 'all'" >> "$CONF"
echo "logging_collector = 'on'" >> "$CONF"
echo "log_min_duration_statement = 0" >> "$CONF"

systemctl restart postgresql 2>/dev/null || service postgresql restart

echo "[+] PostgreSQL logging enabled"

tail -f /var/log/postgresql/postgresql-*.log
