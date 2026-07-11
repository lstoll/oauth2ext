package oauth2as

import "testing"

func TestApplyClientOpts(t *testing.T) {
	t.Run("rejects public client with skip PKCE", func(t *testing.T) {
		_, err := applyClientOpts([]ClientOpt{ClientOptPublic(), ClientOptSkipPKCE()})
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("allows public client alone", func(t *testing.T) {
		co, err := applyClientOpts([]ClientOpt{ClientOptPublic()})
		if err != nil {
			t.Fatal(err)
		}
		if !co.public || co.skipPKCE {
			t.Fatalf("unexpected opts: %+v", co)
		}
	})
}
