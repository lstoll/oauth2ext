package storee2e

import (
	"database/sql"
	"os"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"
	"lds.li/oauth2ext/oauth2as"
)

func TestPostgreSQL(t *testing.T) {
	databaseURL := os.Getenv("OAUTH2EXT_TEST_POSTGRES_URL")
	if databaseURL == "" {
		t.Skip("OAUTH2EXT_TEST_POSTGRES_URL is not set")
	}
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	runStorageE2E(t, db, oauth2as.SQLDialectPostgreSQL, migrationPrefix(t, "postgres"))
}
