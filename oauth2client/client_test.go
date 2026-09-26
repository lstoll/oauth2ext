package oauth2client_test

import (
	"testing"

	"golang.org/x/oauth2"
	"lds.li/oauth2ext/clientjwt"
	"lds.li/oauth2ext/oauth2client"
)

var (
	_ oauth2client.AuthorizationCodeClient = (*oauth2.Config)(nil)
	_ oauth2client.TokenSourceProvider     = (*oauth2.Config)(nil)
	_ oauth2client.Client                  = (*oauth2.Config)(nil)
	_ oauth2client.AuthorizationCodeClient = (*clientjwt.Config)(nil)
	_ oauth2client.TokenSourceProvider     = (*clientjwt.Config)(nil)
	_ oauth2client.Client                  = (*clientjwt.Config)(nil)
)

func TestClientTypes(t *testing.T) {
	if oauth2client.ClientTypeUnspecified.Valid() || oauth2client.ClientType(255).Valid() {
		t.Fatal("unspecified and unknown client types must be rejected")
	}
	if !oauth2client.PublicClient.Valid() || !oauth2client.ConfidentialClient.Valid() {
		t.Fatal("known client types must be valid")
	}
}
