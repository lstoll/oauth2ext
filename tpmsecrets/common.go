package tpmsecrets

import (
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

const (
	signerKeyFile = "tpm_signer_key.blob"
	cacheDataFile = "tpm_cache_data.enc"
)

func IsTPMAvailable() bool {
	_, err := openTPM()
	return err == nil
}

func openTPM() (transport.TPM, error) {
	if socket := os.Getenv("TPM_TEST_SOCKET"); socket != "" {
		conn, err := net.Dial("tcp", socket)
		if err != nil {
			return nil, err
		}
		return transport.FromReadWriteCloser(conn), nil
	}
	return openPlatformTPM()
}

func closeTPM(t transport.TPM) {
	if c, ok := t.(io.Closer); ok {
		c.Close()
	}
}

// getSRK creates a primary key (SRK) in the owner hierarchy.
func getSRK(rwc transport.TPM) (*tpm2.AuthHandle, error) {
	srk := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{},
			},
		},
		InPublic: tpm2.New2B(tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgECC,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				FixedTPM:            true,
				FixedParent:         true,
				SensitiveDataOrigin: true,
				UserWithAuth:        true,
				NoDA:                true,
				Restricted:          true,
				Decrypt:             true,
			},
			Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC,
				&tpm2.TPMSECCParms{
					Symmetric: tpm2.TPMTSymDefObject{
						Algorithm: tpm2.TPMAlgAES,
						KeyBits:   tpm2.NewTPMUSymKeyBits(tpm2.TPMAlgAES, tpm2.TPMKeyBits(128)),
						Mode:      tpm2.NewTPMUSymMode(tpm2.TPMAlgAES, tpm2.TPMAlgCFB),
					},
					Scheme: tpm2.TPMTECCScheme{
						Scheme: tpm2.TPMAlgNull,
					},
					CurveID: tpm2.TPMECCNistP256,
					KDF: tpm2.TPMTKDFScheme{
						Scheme: tpm2.TPMAlgNull,
					},
				},
			),
			Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{}),
		}),
	}

	rsp, err := srk.Execute(rwc)
	if err != nil {
		return nil, fmt.Errorf("creating primary: %w", err)
	}

	return &tpm2.AuthHandle{
		Handle: rsp.ObjectHandle,
		Name:   rsp.Name,
		Auth:   tpm2.PasswordAuth(nil),
	}, nil
}

// flushHandle is a helper to flush a handle and ignore errors (defer usage)
func flushHandle(rwc transport.TPM, handle tpm2.TPMHandle) {
	_, _ = tpm2.FlushContext{FlushHandle: handle}.Execute(rwc)
}

// readBlob reads a file into a byte slice.
func readBlob(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}

// writeBlob writes a byte slice to a file.
func writeBlob(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}
