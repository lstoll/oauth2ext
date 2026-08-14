# oauth2as SQL storage E2E tests

SQLite runs without external services:

```sh
go test ./...
```

To include PostgreSQL:

```sh
docker compose up -d
OAUTH2EXT_TEST_POSTGRES_URL='postgres://oauth2as:oauth2as@localhost:5438/oauth2as_test?sslmode=disable' go test ./...
docker compose down
```
