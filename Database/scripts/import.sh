#!/bin/bash

echo "Importing MongoDB seed files..."

docker cp ../seed/. threatfusion-mongo:/tmp/seed/

for collection in users indicators alerts campaigns reports audit_logs
do
    docker exec threatfusion-mongo mongoimport \
        --db threatfusion \
        --collection $collection \
        --file /tmp/seed/${collection}.json \
        --jsonArray \
        --drop
done

echo "Import completed."
