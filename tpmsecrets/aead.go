package tpmsecrets

import (
	"fmt"

	"github.com/google/go-tpm/tpm2"
)

const maxTPMSealedPartSize = 1 << 20

type sealedBlob struct {
	Public  []byte
	Private []byte
}

type keySealer interface {
	Seal([]byte) (sealedBlob, error)
	Unseal(sealedBlob) ([]byte, error)
}

// tpmKeySealer treats the TPM as a KEK: it seals and unseals short random data
// encryption keys without exposing a general-purpose AEAD abstraction.
type tpmKeySealer struct{}

func (tpmKeySealer) Seal(plaintext []byte) (sealedBlob, error) {
	if len(plaintext) == 0 || len(plaintext) > maxTPMSealedPartSize {
		return sealedBlob{}, fmt.Errorf("invalid plaintext size for TPM sealing")
	}
	rwc, err := openTPM()
	if err != nil {
		return sealedBlob{}, err
	}
	defer closeTPM(rwc)

	srk, err := getSRK(rwc)
	if err != nil {
		return sealedBlob{}, err
	}
	defer flushHandle(rwc, srk.Handle)

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
				SensitiveDataOrigin: false,
				UserWithAuth:        true,
				NoDA:                true,
			},
			Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgKeyedHash,
				&tpm2.TPMSKeyedHashParms{
					Scheme: tpm2.TPMTKeyedHashScheme{Scheme: tpm2.TPMAlgNull},
				},
			),
			Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgKeyedHash, &tpm2.TPM2BDigest{}),
		}),
	}

	rsp, err := create.Execute(rwc)
	if err != nil {
		return sealedBlob{}, fmt.Errorf("tpm create: %w", err)
	}
	return sealedBlob{
		Private: append([]byte(nil), rsp.OutPrivate.Buffer...),
		Public:  tpm2.Marshal(rsp.OutPublic),
	}, nil
}

func (tpmKeySealer) Unseal(blob sealedBlob) ([]byte, error) {
	if len(blob.Public) == 0 || len(blob.Public) > maxTPMSealedPartSize || len(blob.Private) == 0 || len(blob.Private) > maxTPMSealedPartSize {
		return nil, fmt.Errorf("invalid TPM-sealed key")
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
	loadRsp, err := (tpm2.Load{
		ParentHandle: *srk,
		InPrivate:    tpm2.TPM2BPrivate{Buffer: blob.Private},
		InPublic:     *pub,
	}).Execute(rwc)
	if err != nil {
		return nil, fmt.Errorf("tpm load: %w", err)
	}
	defer flushHandle(rwc, loadRsp.ObjectHandle)

	rsp, err := (tpm2.Unseal{
		ItemHandle: tpm2.AuthHandle{
			Handle: loadRsp.ObjectHandle,
			Name:   loadRsp.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
	}).Execute(rwc)
	if err != nil {
		return nil, fmt.Errorf("tpm unseal: %w", err)
	}
	return append([]byte(nil), rsp.OutData.Buffer...), nil
}
