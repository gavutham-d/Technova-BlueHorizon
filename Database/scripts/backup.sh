#!/bin/bash

mkdir -p ../backup

docker exec threatfusion-mongo mongodump \
    --db threatfusion \
    --out /tmp/backup

docker cp threatfusion-mongo:/tmp/backup ../backup

echo "Database backup created."
