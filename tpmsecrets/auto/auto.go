package auto

import (
	"crypto"
	"fmt"
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

	platformsecrets.RegisterPlatformSigner(func() (crypto.Signer, error) {
		s := &tpmsecrets.TPMSigner{Dir: tpmDir}
		if !tpmsecrets.IsTPMAvailable() {
			return nil, fmt.Errorf("TPM not available")
		}
		return s, nil
	})

	platformsecrets.RegisterCredentialCache(&tpmsecrets.TPMCredentialCache{Dir: tpmDir})
}
