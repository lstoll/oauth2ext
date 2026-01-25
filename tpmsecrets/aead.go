package tpmsecrets

import (
	"encoding/json"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/tink-crypto/tink-go/v2/tink"
)

// tpmAEAD implements tink.AEAD using TPM sealing.
// It treats the TPM as a KMS that seals data (keys) to the machine.
type tpmAEAD struct{}

var _ tink.AEAD = (*tpmAEAD)(nil)

type sealedBlob struct {
	Public  []byte
	Private []byte
}

func (t *tpmAEAD) Encrypt(plaintext, associatedData []byte) ([]byte, error) {
	// For KMSEnvelope usage, AAD is typically empty for the DEK encryption.
	// We ignore it anyway, as they TPM does not support arbitrary AAD binding.

	rwc, err := openTPM()
	if err != nil {
		return nil, err
	}
	defer closeTPM(rwc)

	srk, err := getSRK(rwc)
	if err != nil {
		return nil, err
	}
	defer flushHandle(rwc, srk.Handle)

	// Create a KeyedHash object containing the data
	create := tpm2.Create{
		ParentHandle: *srk,
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{},
				Data:     tpm2.NewTPMUSensitiveCreate(&tpm2.TPM2BSensitiveData{Buffer: plaintext}),
			},
		},
		InPublic: tpm2.New2B(tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgKeyedHash,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				FixedTPM:            true,
				FixedParent:         true,
				SensitiveDataOrigin: false, // We provide the data
				UserWithAuth:        true,
				NoDA:                true,
			},
			Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgKeyedHash,
				&tpm2.TPMSKeyedHashParms{
					Scheme: tpm2.TPMTKeyedHashScheme{
						Scheme: tpm2.TPMAlgNull,
					},
				},
			),
			Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgKeyedHash, &tpm2.TPM2BDigest{}),
		}),
	}

	rsp, err := create.Execute(rwc)
	if err != nil {
		return nil, fmt.Errorf("tpm create: %w", err)
	}

	pubBytes := tpm2.Marshal(rsp.OutPublic)

	blob := sealedBlob{
		Private: rsp.OutPrivate.Buffer,
		Public:  pubBytes,
	}

	return json.Marshal(blob)
}

func (t *tpmAEAD) Decrypt(ciphertext, associatedData []byte) ([]byte, error) {
	var blob sealedBlob
	if err := json.Unmarshal(ciphertext, &blob); err != nil {
		return nil, fmt.Errorf("unmarshal sealed data: %w", err)
	}

	rwc, err := openTPM()
	if err != nil {
		return nil, err
	}
	defer closeTPM(rwc)

	srk, err := getSRK(rwc)
	if err != nil {
		return nil, err
	}
	defer flushHandle(rwc, srk.Handle)

	pub, err := tpm2.Unmarshal[tpm2.TPM2BPublic](blob.Public)
	if err != nil {
		return nil, fmt.Errorf("unmarshal public: %w", err)
	}

	load := tpm2.Load{
		ParentHandle: *srk,
		InPrivate:    tpm2.TPM2BPrivate{Buffer: blob.Private},
		InPublic:     *pub,
	}
	loadRsp, err := load.Execute(rwc)
	if err != nil {
		return nil, fmt.Errorf("tpm load: %w", err)
	}
	defer flushHandle(rwc, loadRsp.ObjectHandle)

	unseal := tpm2.Unseal{
		ItemHandle: tpm2.AuthHandle{
			Handle: loadRsp.ObjectHandle,
			Name:   loadRsp.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
	}
	rsp, err := unseal.Execute(rwc)
	if err != nil {
		return nil, fmt.Errorf("tpm unseal: %w", err)
	}

	return rsp.OutData.Buffer, nil
}
