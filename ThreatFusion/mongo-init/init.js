db = db.getSiblingDB("threatfusion");

print("ThreatFusion database initialized.");

db.createCollection("users");
db.createCollection("alerts");
db.createCollection("indicators");
db.createCollection("reports");
db.createCollection("campaigns");
db.createCollection("audit_logs");
