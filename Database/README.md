## Runtime

The application initializes MongoDB automatically through Docker Compose.

No manual database setup is required.

---

## Utility Scripts

Located in:

Database/scripts/

| Script | Purpose |
|---------|----------|
| export.sh | Export collections to JSON |
| import.sh | Restore collections from JSON |
| backup.sh | Create BSON database backup |

Examples:

```bash
cd Database/scripts

./export.sh
```

```bash
./import.sh
```

```bash
./backup.sh
```
