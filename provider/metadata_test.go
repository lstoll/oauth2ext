package provider

import (
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"testing"
)

func TestMetadataExtensionsRoundTrip(t *testing.T) {
	var metadata OIDCProviderMetadata
	if err := unmarshalMetadata([]byte(`{"issuer":"https://issuer.example","vendor_feature":{"enabled":true},"vendor_list":[1,2]}`), &metadata); err != nil {
		t.Fatal(err)
	}
	if len(metadata.Extensions) != 2 {
		t.Fatalf("extensions = %#v, want two members", metadata.Extensions)
	}
	body, err := jsonv2.Marshal(&metadata)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]jsontext.Value
	if err := jsonv2.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"vendor_feature", "vendor_list"} {
		if _, ok := got[name]; !ok {
			t.Errorf("round trip lost extension %q: %s", name, body)
		}
	}
}

func TestMetadataRejectsCaseVariantOfKnownField(t *testing.T) {
	for _, body := range []string{
		`{"issuer":"https://issuer.example","Issuer":"https://attacker.example"}`,
		`{"issuer":"https://issuer.example","iſsuer":"https://attacker.example"}`,
		`{"jwks_uri":"https://issuer.example/jwks","JWKS_URI":"https://attacker.example/jwks"}`,
	} {
		var metadata OIDCProviderMetadata
		if err := unmarshalMetadata([]byte(body), &metadata); err == nil {
			t.Errorf("unmarshalMetadata(%s) succeeded, want ambiguous name error", body)
		}
	}
}

func TestProviderMetadataSnapshotsAreIndependent(t *testing.T) {
	input := &OIDCProviderMetadata{
		ScopesSupported: []string{"openid"},
		Extensions:      map[string]jsontext.Value{"vendor": jsontext.Value(`{"enabled":true}`)},
	}
	p := New(input)
	input.ScopesSupported[0] = "mutated input"
	input.Extensions["vendor"][2] = 'X'

	snapshot := p.MetadataSnapshot()
	if snapshot.ScopesSupported[0] != "openid" {
		t.Fatalf("constructor retained input slice: %#v", snapshot.ScopesSupported)
	}
	snapshot.ScopesSupported[0] = "mutated snapshot"
	snapshot.Extensions["vendor"][2] = 'Y'
	if got := p.MetadataSnapshot().ScopesSupported[0]; got != "openid" {
		t.Fatalf("snapshot mutation changed provider metadata: %q", got)
	}
	if got := string(p.MetadataSnapshot().Extensions["vendor"]); got != `{"enabled":true}` {
		t.Fatalf("extension mutation changed provider metadata: %s", got)
	}
}
