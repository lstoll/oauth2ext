package storee2e

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"

	"lds.li/oauth2ext/oauth2as"
	_ "modernc.org/sqlite"
)

func TestSQLite(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "oauth2as.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	runStorageE2E(t, db, oauth2as.SQLDialectSQLite, migrationPrefix(t, "sqlite"))
}

func TestSQLiteMigrate(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "oauth2as.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	prefix := migrationPrefix(t, "migrate")
	store, err := oauth2as.NewSQLStorage(db, oauth2as.SQLStorageOptions{Dialect: oauth2as.SQLDialectSQLite, TablePrefix: prefix})
	if err != nil {
		t.Fatal(err)
	}
	applyMigrations(t, db, store, prefix)

	var table string
	if err := db.QueryRow(`SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?`, prefix+"_grants").Scan(&table); err != nil {
		t.Fatalf("prefixed grants table missing: %v", err)
	}

	if _, err := db.Exec(`INSERT INTO ` + prefix + `_schema_migrations (version, name, applied_at) VALUES (99, 'future', '1970-01-01T00:00:00.000000Z')`); err != nil {
		t.Fatal(err)
	}
	err = store.Migrate(t.Context())
	if err == nil || !strings.Contains(err.Error(), "newer than this library") {
		t.Fatalf("Migrate() error = %v, want newer-schema error", err)
	}
}
