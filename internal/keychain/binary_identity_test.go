//go:build darwin && cgo

package keychain

import "testing"

func TestGetSelfCDHashes(t *testing.T) {
	hash, err := GetSelfCDHashes()
	if err != nil {
		t.Fatalf("GetSelfCDHash failed: %v", err)
	}
	t.Logf("CDHashes: %#v", hash)
}

func TestGetBinaryIdentity(t *testing.T) {
	hash, err := GetBinaryIdentity()
	if err != nil {
		t.Fatalf("GetBinaryIdentity failed: %v", err)
	}
	t.Logf("BinaryIdentity: %s", hash)
}

func TestHashExecutableFile(t *testing.T) {
	hash, err := hashExecutableFile()
	if err != nil {
		t.Fatalf("hashExecutableFile failed: %v", err)
	}
	t.Logf("hashExecutableFile: %s", hash)
}
