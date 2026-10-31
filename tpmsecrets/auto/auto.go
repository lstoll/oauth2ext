package auto

import (
	"os"
	"path/filepath"

	"lds.li/oauth2ext/internal/platformsecrets"
	"lds.li/oauth2ext/tpmsecrets"
)

func init() {
	// Register the TPM implementation.

	cacheDir, err := os.UserCacheDir()
	if err != nil {
		// Fallback or ignore
		return
	}
	tpmDir := filepath.Join(cacheDir, "lds-oauth2ext-tpm")

	platformsecrets.Register(&tpmsecrets.TPMCredentialCache{Dir: tpmDir})
}
