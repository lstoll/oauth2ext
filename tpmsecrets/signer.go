package tpmsecrets

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/big"
	"path/filepath"
	"sync"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

type TPMSigner struct {
	Dir string

	mu        sync.Mutex
	publicKey crypto.PublicKey
}

func (s *TPMSigner) Public() crypto.PublicKey {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.publicKey != nil {
		return s.publicKey
	}

	rwc, err := openTPM()
	if err != nil {
		return nil
	}
	defer closeTPM(rwc)

	keyHandle, err := s.loadKey(rwc)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			keyHandle, err = s.generateKey(rwc)
			if err != nil {
				return nil
			}
		} else {
			return nil
		}
	}
	defer flushHandle(rwc, keyHandle.Handle)

	pub, err := getKeyPublic(rwc, keyHandle.Handle)
	if err != nil {
		return nil
	}
	s.publicKey = pub
	return pub
}

func (s *TPMSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rwc, err := openTPM()
	if err != nil {
		return nil, err
	}
	defer closeTPM(rwc)

	keyHandle, err := s.loadKey(rwc)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			keyHandle, err = s.generateKey(rwc)
			if err != nil {
				return nil, fmt.Errorf("generating key: %w", err)
			}
		} else {
			return nil, fmt.Errorf("loading key: %w", err)
		}
	}
	defer flushHandle(rwc, keyHandle.Handle)

	// Sign
	sign := tpm2.Sign{
		KeyHandle: *keyHandle,
		Digest: tpm2.TPM2BDigest{
			Buffer: digest,
		},
		InScheme: tpm2.TPMTSigScheme{
			Scheme: tpm2.TPMAlgECDSA,
			Details: tpm2.NewTPMUSigScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSchemeHash{
				HashAlg: tpm2.TPMAlgSHA256,
			}),
		},
		Validation: tpm2.TPMTTKHashCheck{
			Tag: tpm2.TPMSTHashCheck,
		},
	}

	rsp, err := sign.Execute(rwc)
	if err != nil {
		return nil, fmt.Errorf("tpm sign: %w", err)
	}

	eccSig, err := rsp.Signature.Signature.ECDSA()
	if err != nil {
		return nil, fmt.Errorf("getting ecdsa signature: %w", err)
	}

	r := big.NewInt(0).SetBytes(eccSig.SignatureR.Buffer)
	sVal := big.NewInt(0).SetBytes(eccSig.SignatureS.Buffer)

	return asn1.Marshal(struct{ R, S *big.Int }{r, sVal})
}

// loadKey loads the key from disk and into the TPM. Returns handle.
func (s *TPMSigner) loadKey(rwc transport.TPM) (*tpm2.AuthHandle, error) {
	path := filepath.Join(s.Dir, signerKeyFile)
	data, err := readBlob(path)
	if err != nil {
		return nil, err
	}

	var blob struct {
		Private []byte
		Public  []byte
	}
	if err := json.Unmarshal(data, &blob); err != nil {
		return nil, fmt.Errorf("unmarshal key: %w", err)
	}

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

	return &tpm2.AuthHandle{
		Handle: loadRsp.ObjectHandle,
		Name:   loadRsp.Name,
		Auth:   tpm2.PasswordAuth(nil),
	}, nil
}

func (s *TPMSigner) generateKey(rwc transport.TPM) (*tpm2.AuthHandle, error) {
	srk, err := getSRK(rwc)
	if err != nil {
		return nil, err
	}
	defer flushHandle(rwc, srk.Handle)

	create := tpm2.Create{
		ParentHandle: *srk,
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
				SignEncrypt:         true,
			},
			Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC,
				&tpm2.TPMSECCParms{
					Symmetric: tpm2.TPMTSymDefObject{
						Algorithm: tpm2.TPMAlgNull,
					},
					Scheme: tpm2.TPMTECCScheme{
						Scheme: tpm2.TPMAlgECDSA,
						Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDSA,
							&tpm2.TPMSSigSchemeECDSA{HashAlg: tpm2.TPMAlgSHA256},
						),
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

	rsp, err := create.Execute(rwc)
	if err != nil {
		return nil, fmt.Errorf("tpm create: %w", err)
	}

	pubBytes := tpm2.Marshal(rsp.OutPublic)

	blob := struct {
		Private []byte
		Public  []byte
	}{
		Private: rsp.OutPrivate.Buffer,
		Public:  pubBytes,
	}

	load := tpm2.Load{
		ParentHandle: *srk,
		InPrivate:    rsp.OutPrivate,
		InPublic:     rsp.OutPublic,
	}

	loadRsp, err := load.Execute(rwc)
	if err != nil {
		return nil, fmt.Errorf("tpm load after create: %w", err)
	}

	jsonBytes, _ := json.Marshal(blob)
	if err := writeBlob(filepath.Join(s.Dir, signerKeyFile), jsonBytes); err != nil {
		return nil, err
	}

	return &tpm2.AuthHandle{
		Handle: loadRsp.ObjectHandle,
		Name:   loadRsp.Name,
		Auth:   tpm2.PasswordAuth(nil),
	}, nil
}

func getKeyPublic(rwc transport.TPM, handle tpm2.TPMHandle) (crypto.PublicKey, error) {
	rp := tpm2.ReadPublic{ObjectHandle: handle}
	rsp, err := rp.Execute(rwc)
	if err != nil {
		return nil, err
	}

	pub, err := rsp.OutPublic.Contents()
	if err != nil {
		return nil, err
	}

	ecc, err := pub.Parameters.ECCDetail()
	if err != nil {
		return nil, err
	}

	if ecc.CurveID != tpm2.TPMECCNistP256 {
		return nil, fmt.Errorf("unsupported curve: %v", ecc.CurveID)
	}

	unique, err := pub.Unique.ECC()
	if err != nil {
		return nil, err
	}

	x := big.NewInt(0).SetBytes(unique.X.Buffer)
	y := big.NewInt(0).SetBytes(unique.Y.Buffer)

	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}, nil
}
