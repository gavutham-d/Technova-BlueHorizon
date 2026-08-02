# Threat Fusion Database Schema

## Database

```
threatfusion
```

---

# Collections

## users

Stores authenticated platform users.

| Field | Type | Description |
|-------|------|-------------|
| _id | ObjectId | Primary Key |
| username | String | Unique username |
| email | String | User email |
| password_hash | String | Hashed password |
| role | String | Admin / Analyst / ReadOnly |
| created_at | Date | Creation timestamp |

---

## indicators

Stores all CTI indicators.

| Field | Type |
|------|------|
| _id | ObjectId |
| value | String |
| ioc_type | String |
| source | String |
| severity | String |
| risk_score | Float |
| malware | String |
| campaign | String |
| cves | Array |
| created_at | Date |

---

## alerts

Generated security alerts.

| Field | Type |
|------|------|
| _id | ObjectId |
| indicator_id | ObjectId |
| status | String |
| assigned_to | String |
| trigger_reason | String |
| created_at | Date |

---

## campaigns

Threat campaign intelligence.

| Field | Type |
|------|------|
| _id | ObjectId |
| campaign_name | String |
| actor | String |
| techniques | Array |
| indicators | Array |

---

## reports

Dashboard analytics.

| Field | Type |
|------|------|
| _id | ObjectId |
| report_name | String |
| generated_at | Date |
| metrics | Object |

---

## audit_logs

System audit records.

| Field | Type |
|------|------|
| _id | ObjectId |
| username | String |
| action | String |
| ip_address | String |
| timestamp | Date |

---

# Relationships

users
    │
    ├──────────────┐
    │              │
alerts        audit_logs
    │
indicator_id
    │
    ▼
indicators
    │
    ▼
campaigns
