//go:build !windows

package tpmsecrets

import (
	"os"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
)

const (
	tpmDevicePath         = "/dev/tpmrm0"
	fallbackTpmDevicePath = "/dev/tpm0"
)

func openPlatformTPM() (transport.TPM, error) {
	if _, err := os.Stat(tpmDevicePath); err == nil {
		return linuxtpm.Open(tpmDevicePath)
	}
	return linuxtpm.Open(fallbackTpmDevicePath)
}
