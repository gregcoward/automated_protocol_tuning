#!/bin/sh
# Wrapper entrypoint for VictoriaMetrics supporting UI-configurable retention and deduplication
set -eu

RUNTIME_ENV="/config/vm-runtime.env"
if [ -f "$RUNTIME_ENV" ]; then
  # shellcheck disable=SC1090
  . "$RUNTIME_ENV"
fi

RETENTION="${VM_RETENTION_PERIOD:-30d}"
DEDUP="${VM_DEDUP_INTERVAL:-15s}"
STORAGE_PATH="${VM_STORAGE_DATA_PATH:-/victoria-metrics-data}"

exec /victoria-metrics-prod \
  -storageDataPath="$STORAGE_PATH" \
  -retentionPeriod="$RETENTION" \
  -dedup.minScrapeInterval="$DEDUP" \
  -httpListenAddr=":8428" \
  -search.latencyOffset="5s"
