#!/bin/bash

echo "Exporting MongoDB collections..."

mkdir -p ../seed

docker exec threatfusion-mongo mongoexport \
  --db threatfusion \
  --collection users \
  --jsonArray \
  --out /tmp/users.json

docker cp threatfusion-mongo:/tmp/users.json ../seed/users.json

docker exec threatfusion-mongo mongoexport \
  --db threatfusion \
  --collection indicators \
  --jsonArray \
  --out /tmp/indicators.json

docker cp threatfusion-mongo:/tmp/indicators.json ../seed/indicators.json

docker exec threatfusion-mongo mongoexport \
  --db threatfusion \
  --collection alerts \
  --jsonArray \
  --out /tmp/alerts.json

docker cp threatfusion-mongo:/tmp/alerts.json ../seed/alerts.json

docker exec threatfusion-mongo mongoexport \
  --db threatfusion \
  --collection campaigns \
  --jsonArray \
  --out /tmp/campaigns.json

docker cp threatfusion-mongo:/tmp/campaigns.json ../seed/campaigns.json

docker exec threatfusion-mongo mongoexport \
  --db threatfusion \
  --collection reports \
  --jsonArray \
  --out /tmp/reports.json

docker cp threatfusion-mongo:/tmp/reports.json ../seed/reports.json

docker exec threatfusion-mongo mongoexport \
  --db threatfusion \
  --collection audit_logs \
  --jsonArray \
  --out /tmp/audit_logs.json

docker cp threatfusion-mongo:/tmp/audit_logs.json ../seed/audit_logs.json

echo "Export completed."
