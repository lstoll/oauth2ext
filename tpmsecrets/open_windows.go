//go:build windows

package tpmsecrets

import (
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/windowstpm"
)

func openPlatformTPM() (transport.TPM, error) {
	return windowstpm.Open()
}
