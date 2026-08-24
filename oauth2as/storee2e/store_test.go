package storee2e

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"database/sql"
	jsonv2 "encoding/json/v2"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"lds.li/oauth2ext/dpop"
	"lds.li/oauth2ext/oauth2as"
)

type clientSource struct{}

func (clientSource) IsValidClientID(context.Context, string) (bool, error) { return true, nil }
func (clientSource) ClientSecrets(context.Context, string) ([]string, error) {
	return []string{"client-secret"}, nil
}
func (clientSource) RedirectURIs(context.Context, string) ([]string, error) {
	return []string{"https://client.example/callback"}, nil
}
func (clientSource) ClientOpts(context.Context, string) ([]oauth2as.ClientOpt, error) {
	return []oauth2as.ClientOpt{oauth2as.ClientOptSkipPKCE()}, nil
}

func applyMigrations(t *testing.T, db *sql.DB, store *oauth2as.Storage, prefix string) {
	t.Helper()
	resetStorage(t, db, prefix)
	if err := store.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := store.Migrate(t.Context()); err != nil {
		t.Fatalf("idempotent migrate: %v", err)
	}
	t.Cleanup(func() { resetStorage(t, db, prefix) })
}

func resetStorage(t *testing.T, db *sql.DB, prefix string) {
	t.Helper()
	for _, table := range []string{
		prefix + "_refresh_sessions",
		prefix + "_refresh_tokens",
		prefix + "_authorization_codes",
		prefix + "_grants",
		prefix + "_schema_migrations",
	} {
		if _, err := db.ExecContext(context.Background(), "DROP TABLE IF EXISTS "+table); err != nil {
			t.Fatalf("drop %s: %v", table, err)
		}
	}
}

func runStorageE2E(t *testing.T, db *sql.DB, dialect oauth2as.SQLDialect, prefix string) {
	t.Helper()
	store, err := oauth2as.NewSQLStorage(db, oauth2as.SQLStorageOptions{Dialect: dialect, TablePrefix: prefix})
	if err != nil {
		t.Fatal(err)
	}
	applyMigrations(t, db, store, prefix)
	assertSQLColumnTypes(t, db, dialect, prefix)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := oauth2as.NewLocalJWTSignerForKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dpopKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dpopSigner, err := dpop.NewSigner(dpopKey)
	if err != nil {
		t.Fatal(err)
	}
	server, err := oauth2as.NewServer(oauth2as.Config{
		Issuer:                          "https://issuer.example",
		Storage:                         store,
		Clients:                         clientSource{},
		Signer:                          signer,
		Verifier:                        signer,
		DPoPVerifier:                    &dpop.Verifier{},
		Logger:                          slog.New(slog.NewTextHandler(os.Stderr, nil)),
		RefreshTokenValidity:            time.Hour,
		RefreshTokenRotationGracePeriod: time.Minute,
		TokenHandler: func(context.Context, *oauth2as.TokenRequest) (*oauth2as.TokenResponse, error) {
			return &oauth2as.TokenResponse{}, nil
		},
		UserinfoHandler: func(context.Context, *oauth2as.UserinfoRequest) (*oauth2as.UserinfoResponse, error) {
			return &oauth2as.UserinfoResponse{Identity: map[string]any{"sub": "user-1"}}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	codeForm := tokenForm("authorization_code", authorize(t, server, "user-1"))
	tokens := raceToken(t, server, codeForm, dpopSigner, "concurrent code exchange")
	if tokens["token_type"] != "DPoP" {
		t.Fatalf("token_type = %v, want DPoP", tokens["token_type"])
	}
	refresh, _ := tokens["refresh_token"].(string)
	if refresh == "" {
		t.Fatal("token response has no refresh token")
	}
	refreshForm := tokenForm("refresh_token", refresh)
	raceToken(t, server, refreshForm, dpopSigner, "concurrent refresh rotation")
	// Once the winning rotation is committed, retrying the old token within the
	// configured grace period succeeds and advances the same token family.
	if exchange(t, server, refreshForm, dpopSigner)["access_token"] == "" {
		t.Fatal("refresh response has no access token")
	}

	var lastRefresh string
	for range 2 {
		issued := exchange(t, server, tokenForm("authorization_code", authorize(t, server, "user-1")), dpopSigner)
		lastRefresh, _ = issued["refresh_token"].(string)
	}
	seen := make(map[string]struct{})
	cursor := ""
	for range 4 {
		page, err := server.ListRefreshSessions(t.Context(), oauth2as.RefreshSessionQuery{UserID: "user-1", Limit: 1, Cursor: cursor})
		if err != nil {
			t.Fatal(err)
		}
		if len(page.Sessions) == 0 {
			break
		}
		if len(page.Sessions) != 1 {
			t.Fatalf("page size = %d, want 1", len(page.Sessions))
		}
		grantID := page.Sessions[0].GrantID
		if _, dup := seen[grantID]; dup {
			t.Fatalf("pagination repeated grant %s", grantID)
		}
		seen[grantID] = struct{}{}
		cursor = page.NextCursor
		if cursor == "" {
			break
		}
	}
	if len(seen) != 3 {
		t.Fatalf("paginated %d sessions, want 3", len(seen))
	}
	if cursor != "" {
		t.Fatal("expected pagination to end after 3 sessions")
	}

	page, err := server.ListRefreshSessions(t.Context(), oauth2as.RefreshSessionQuery{UserID: "user-1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Sessions) != 3 {
		t.Fatalf("got %d active refresh sessions, want 3", len(page.Sessions))
	}
	if !slices.Equal(page.Sessions[0].GrantedScopes, []string{"openid", "offline_access"}) {
		t.Fatalf("granted scopes = %q, want openid offline_access", page.Sessions[0].GrantedScopes)
	}
	if err := server.RevokeRefreshSession(t.Context(), "user-1", page.Sessions[0].GrantID); err != nil {
		t.Fatal(err)
	}
	page, err = server.ListRefreshSessions(t.Context(), oauth2as.RefreshSessionQuery{UserID: "user-1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Sessions) != 2 {
		t.Fatalf("got %d sessions after revocation, want 2", len(page.Sessions))
	}

	result, err := store.Cleanup(t.Context(), oauth2as.CleanupOptions{Before: time.Now().Add(24 * time.Hour), Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if result.Deleted == 0 {
		t.Fatal("cleanup deleted no records")
	}
	page, err = server.ListRefreshSessions(t.Context(), oauth2as.RefreshSessionQuery{UserID: "user-1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Sessions) != 0 {
		t.Fatalf("got %d sessions after cleanup, want 0", len(page.Sessions))
	}
	if lastRefresh == "" {
		t.Fatal("missing refresh token for post-cleanup check")
	}
	status, body := tokenResponse(server, tokenForm("refresh_token", lastRefresh), dpopSigner)
	if status != http.StatusBadRequest || body["error"] != "invalid_grant" {
		t.Fatalf("refresh after cleanup = %d %v, want 400 invalid_grant", status, body)
	}
}

func assertSQLColumnTypes(t *testing.T, db *sql.DB, dialect oauth2as.SQLDialect, prefix string) {
	t.Helper()
	table := prefix + "_grants"
	switch dialect {
	case oauth2as.SQLDialectSQLite:
		var schema string
		if err := db.QueryRow(`SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?`, table).Scan(&schema); err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{
			"id TEXT PRIMARY KEY",
			"granted_at TEXT NOT NULL",
			"user_id TEXT NOT NULL",
			"granted_scopes JSON NOT NULL",
			"metadata BLOB",
		} {
			if !strings.Contains(schema, want) {
				t.Fatalf("sqlite %s schema = %s, want %q", table, schema, want)
			}
		}
	case oauth2as.SQLDialectPostgreSQL:
		assertType := func(table, column, want string) {
			t.Helper()
			var got string
			err := db.QueryRow(
				`SELECT data_type FROM information_schema.columns WHERE table_name = $1 AND column_name = $2`,
				table, column,
			).Scan(&got)
			if err != nil {
				t.Fatalf("%s.%s: %v", table, column, err)
			}
			if got != want {
				t.Fatalf("%s.%s type = %q, want %q", table, column, got, want)
			}
		}
		assertType(table, "id", "uuid")
		assertType(table, "granted_at", "timestamp with time zone")
		assertType(table, "user_id", "text")
		assertType(table, "granted_scopes", "jsonb")
		assertType(table, "metadata", "bytea")
		var replacedBy string
		err := db.QueryRow(
			`SELECT data_type FROM information_schema.columns WHERE table_name = $1 AND column_name = 'replaced_by_id'`,
			prefix+"_refresh_tokens",
		).Scan(&replacedBy)
		if err != nil {
			t.Fatal(err)
		}
		if replacedBy != "uuid" {
			t.Fatalf("replaced_by_id type = %q, want uuid", replacedBy)
		}
	}
}

func authorize(t *testing.T, server *oauth2as.Server, userID string) string {
	t.Helper()
	authURL := "https://issuer.example/authorize?" + url.Values{
		"response_type": {"code"},
		"client_id":     {"client-1"},
		"redirect_uri":  {"https://client.example/callback"},
		"scope":         {"openid offline_access"},
		"state":         {"state"},
	}.Encode()
	authRequest, err := server.ParseAuthRequest(httptest.NewRequest(http.MethodGet, authURL, nil))
	if err != nil {
		t.Fatal(err)
	}
	redirect, err := server.GrantAuth(t.Context(), &oauth2as.AuthGrant{
		Request:       authRequest,
		GrantedScopes: authRequest.Scopes,
		UserID:        userID,
	})
	if err != nil {
		t.Fatal(err)
	}
	redirectURL, err := url.Parse(redirect)
	if err != nil {
		t.Fatal(err)
	}
	code := redirectURL.Query().Get("code")
	if code == "" {
		t.Fatal("authorization response has no code")
	}
	return code
}

func tokenForm(grantType, credential string) url.Values {
	form := url.Values{
		"grant_type":    {grantType},
		"redirect_uri":  {"https://client.example/callback"},
		"client_id":     {"client-1"},
		"client_secret": {"client-secret"},
	}
	if grantType == "authorization_code" {
		form.Set("code", credential)
	} else {
		form.Set("refresh_token", credential)
	}
	return form
}

func raceToken(t *testing.T, server *oauth2as.Server, form url.Values, signer *dpop.Signer, name string) map[string]any {
	t.Helper()
	type tokenResult struct {
		status int
		body   map[string]any
	}
	results := make(chan tokenResult, 2)
	for range 2 {
		go func() {
			status, body := tokenResponse(server, form, signer)
			results <- tokenResult{status: status, body: body}
		}()
	}
	var winner map[string]any
	successes, failures := 0, 0
	for range 2 {
		result := <-results
		if result.status == http.StatusOK {
			successes++
			winner = result.body
			continue
		}
		failures++
		if result.status != http.StatusBadRequest || result.body["error"] != "invalid_grant" {
			t.Fatalf("%s loser = %d %v, want 400 invalid_grant", name, result.status, result.body)
		}
	}
	if successes != 1 || failures != 1 {
		t.Fatalf("%s produced %d successes and %d failures, want 1 each", name, successes, failures)
	}
	return winner
}

func exchange(t *testing.T, server *oauth2as.Server, form url.Values, signer *dpop.Signer) map[string]any {
	t.Helper()
	status, response := tokenResponse(server, form, signer)
	if status != http.StatusOK {
		t.Fatalf("token endpoint returned %d: %v", status, response)
	}
	return response
}

func tokenResponse(server *oauth2as.Server, form url.Values, signer *dpop.Signer) (int, map[string]any) {
	req := httptest.NewRequest(http.MethodPost, "https://issuer.example/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	proof, err := signer.SignAndEncode(dpop.ProofOptions{HTTPMethod: http.MethodPost, HTTPURI: "https://issuer.example/token"})
	if err != nil {
		return 0, map[string]any{"proof_error": err.Error()}
	}
	req.Header.Set("DPoP", proof)
	rec := httptest.NewRecorder()
	server.TokenHandler(rec, req)
	var response map[string]any
	if err := jsonv2.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		response = map[string]any{"decode_error": err.Error(), "body": rec.Body.String()}
	}
	return rec.Code, response
}

func TestConstructorAndMigrationValidation(t *testing.T) {
	if _, err := oauth2as.NewSQLStorage(nil, oauth2as.SQLStorageOptions{Dialect: oauth2as.SQLDialectSQLite}); err == nil {
		t.Fatal("nil database accepted")
	}
	db := new(sql.DB)
	for _, prefix := range []string{"UPPER", "has-hyphen", "" + strings.Repeat("a", 64)} {
		if _, err := oauth2as.NewSQLStorage(db, oauth2as.SQLStorageOptions{Dialect: oauth2as.SQLDialectPostgreSQL, TablePrefix: prefix}); err == nil {
			t.Errorf("invalid prefix %q accepted", prefix)
		}
	}
	if _, err := oauth2as.NewSQLStorage(db, oauth2as.SQLStorageOptions{Dialect: "unknown"}); err == nil {
		t.Fatal("unknown dialect accepted")
	}
}

func migrationPrefix(t *testing.T, name string) string {
	t.Helper()
	return fmt.Sprintf("oauth2as_%s", name)
}
