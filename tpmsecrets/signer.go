package tpmsecrets

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// dpopHandleVersion is the first byte of a DPoP key handle. The handle is:
//
//	version (1 byte) | uint32 BE length | TPM2B_PUBLIC | uint32 BE length | TPM2B_PRIVATE
//
// where the parts are the marshaled TPM structures, wrapped by the SRK.
const dpopHandleVersion = 1

// NewDPoPKey creates a new P-256 signing key under the SRK. The returned
// handle is the wrapped key, and is only usable on this TPM. Nothing is
// persisted by this call.
func (c *TPMCredentialCache) NewDPoPKey() ([]byte, crypto.Signer, error) {
	rwc, err := openTPM()
	if err != nil {
		return nil, nil, err
	}
	defer closeTPM(rwc)

	srk, err := getSRK(rwc)
	if err != nil {
		return nil, nil, err
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
		return nil, nil, fmt.Errorf("tpm create: %w", err)
	}

	pubBlob := tpm2.Marshal(rsp.OutPublic)
	handle, err := encodeDPoPHandle(pubBlob, rsp.OutPrivate.Buffer)
	if err != nil {
		return nil, nil, err
	}
	signer, err := newTPMSigner(pubBlob, rsp.OutPrivate.Buffer)
	if err != nil {
		return nil, nil, err
	}
	return handle, signer, nil
}

// LoadDPoPKey returns a signer for a handle returned by NewDPoPKey.
func (c *TPMCredentialCache) LoadDPoPKey(handle []byte) (crypto.Signer, error) {
	pub, priv, err := decodeDPoPHandle(handle)
	if err != nil {
		return nil, err
	}
	return newTPMSigner(pub, priv)
}

func encodeDPoPHandle(pub, priv []byte) ([]byte, error) {
	if len(pub) == 0 || len(pub) > maxTPMSealedPartSize || len(priv) == 0 || len(priv) > maxTPMSealedPartSize {
		return nil, errors.New("invalid TPM key blob size")
	}
	out := make([]byte, 0, 1+8+len(pub)+len(priv))
	out = append(out, dpopHandleVersion)
	out = binary.BigEndian.AppendUint32(out, uint32(len(pub)))
	out = append(out, pub...)
	out = binary.BigEndian.AppendUint32(out, uint32(len(priv)))
	out = append(out, priv...)
	return out, nil
}

func decodeDPoPHandle(handle []byte) (pub, priv []byte, err error) {
	bad := func(msg string) error { return fmt.Errorf("invalid TPM DPoP key handle: %s", msg) }
	if len(handle) < 1 {
		return nil, nil, bad("empty")
	}
	if handle[0] != dpopHandleVersion {
		return nil, nil, bad(fmt.Sprintf("unsupported version %d", handle[0]))
	}
	rest := handle[1:]
	part := func(name string) ([]byte, error) {
		if len(rest) < 4 {
			return nil, bad("truncated " + name + " length")
		}
		n := binary.BigEndian.Uint32(rest[:4])
		rest = rest[4:]
		if n == 0 || n > maxTPMSealedPartSize {
			return nil, bad("invalid " + name + " size")
		}
		if uint64(len(rest)) < uint64(n) {
			return nil, bad("truncated " + name)
		}
		p := rest[:n:n]
		rest = rest[n:]
		return p, nil
	}
	if pub, err = part("public"); err != nil {
		return nil, nil, err
	}
	if priv, err = part("private"); err != nil {
		return nil, nil, err
	}
	if len(rest) != 0 {
		return nil, nil, bad("trailing data")
	}
	return pub, priv, nil
}

type tpmSigner struct {
	public  *ecdsa.PublicKey
	pubBlob []byte
	private []byte
}

func newTPMSigner(pubBlob, priv []byte) (*tpmSigner, error) {
	pub, err := tpm2.Unmarshal[tpm2.TPM2BPublic](pubBlob)
	if err != nil {
		return nil, fmt.Errorf("unmarshal public: %w", err)
	}
	key, err := eccPublicKey(pub)
	if err != nil {
		return nil, err
	}
	return &tpmSigner{public: key, pubBlob: pubBlob, private: priv}, nil
}

func (s *tpmSigner) Public() crypto.PublicKey { return s.public }

func (s *tpmSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts == nil || opts.HashFunc() != crypto.SHA256 || len(digest) != crypto.SHA256.Size() {
		return nil, errors.New("tpm signer requires a SHA-256 digest")
	}

	rwc, err := openTPM()
	if err != nil {
		return nil, err
	}
	defer closeTPM(rwc)

	keyHandle, err := s.load(rwc)
	if err != nil {
		return nil, err
	}
	defer flushHandle(rwc, keyHandle.Handle)

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

// load loads the wrapped key into the TPM under a fresh SRK.
func (s *tpmSigner) load(rwc transport.TPM) (*tpm2.AuthHandle, error) {
	srk, err := getSRK(rwc)
	if err != nil {
		return nil, err
	}
	defer flushHandle(rwc, srk.Handle)

	pub, err := tpm2.Unmarshal[tpm2.TPM2BPublic](s.pubBlob)
	if err != nil {
		return nil, fmt.Errorf("unmarshal public: %w", err)
	}

	load := tpm2.Load{
		ParentHandle: *srk,
		InPrivate:    tpm2.TPM2BPrivate{Buffer: s.private},
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

// eccPublicKey converts a TPM public area for a P-256 ECDSA signing key to an
// ecdsa.PublicKey.
func eccPublicKey(p *tpm2.TPM2BPublic) (*ecdsa.PublicKey, error) {
	pub, err := p.Contents()
	if err != nil {
		return nil, err
	}
	if pub.Type != tpm2.TPMAlgECC {
		return nil, fmt.Errorf("unsupported key type: %v", pub.Type)
	}
	if !pub.ObjectAttributes.SignEncrypt || pub.ObjectAttributes.Restricted {
		return nil, errors.New("key is not a signing key")
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

	x, y := unique.X.Buffer, unique.Y.Buffer
	const coordSize = 32
	if len(x) > coordSize || len(y) > coordSize {
		return nil, fmt.Errorf("invalid P-256 public key coordinates")
	}
	uncompressed := make([]byte, 1+2*coordSize)
	uncompressed[0] = 0x04
	copy(uncompressed[1+coordSize-len(x):1+coordSize], x)
	copy(uncompressed[1+2*coordSize-len(y):], y)
	return ecdsa.ParseUncompressedPublicKey(elliptic.P256(), uncompressed)
}
