
{
  "$schema": "node_modules/wrangler/config-schema.json",
  "name": "frendio-api",
  "main": "worker.js",
  "compatibility_date": "2026-11-01",
  "workers_dev": true,
  "d1_databases": [
    {
      "binding": "DB",
      "database_name": "frendio-db",
      "database_id": "dd60c8f9-3f16-4b4e-9f8a-4e7c5600df64"
    }
  ],
  "durable_objects": {
    "bindings": [
      {
        "name": "MATCHMAKER",
        "class_name": "Matchmaker"
      },
      {
        "name": "CHATROOM",
        "class_name": "ChatRoom"
      }
    ]
  },
  "migrations": [
    {
      "tag": "v1",
      "new_sqlite_classes": ["Matchmaker"]
    },
    {
      "tag": "v2",
      "new_sqlite_classes": ["ChatRoom"]
    }
  ]
}
