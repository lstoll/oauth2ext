package tpmsecrets

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	cacheEnvelopeVersion   = 1
	cacheEnvelopeAES256GCM = 1
	cacheDEKSize           = 32
	cacheEnvelopeFixedSize = 14 // magic, version, algorithm, and two uint32 lengths
	maxCacheEnvelopeSize   = 16 << 20
)

var (
	cacheEnvelopeMagic = []byte{'o', '2', 't', 'c'}
	errInvalidCache    = errors.New("invalid TPM credential cache")
)

func encryptCredentialCache(sealer keySealer, plaintext []byte) ([]byte, error) {
	if sealer == nil {
		return nil, fmt.Errorf("TPM credential cache: missing key sealer")
	}
	if len(plaintext) > maxCacheEnvelopeSize {
		return nil, fmt.Errorf("TPM credential cache plaintext is too large")
	}

	var dek [cacheDEKSize]byte
	if _, err := rand.Read(dek[:]); err != nil {
		return nil, fmt.Errorf("generating cache data key: %w", err)
	}
	defer clear(dek[:])

	wrapped, err := sealer.Seal(dek[:])
	if err != nil {
		return nil, fmt.Errorf("sealing cache data key: %w", err)
	}
	if len(wrapped.Public) == 0 || len(wrapped.Public) > maxTPMSealedPartSize || len(wrapped.Private) == 0 || len(wrapped.Private) > maxTPMSealedPartSize {
		return nil, fmt.Errorf("sealing cache data key returned an invalid blob")
	}

	aead, err := cacheAEAD(dek)
	if err != nil {
		return nil, err
	}
	prefix := make([]byte, cacheEnvelopeFixedSize, cacheEnvelopeFixedSize+len(wrapped.Public)+len(wrapped.Private)+aead.NonceSize())
	copy(prefix, cacheEnvelopeMagic)
	prefix[4] = cacheEnvelopeVersion
	prefix[5] = cacheEnvelopeAES256GCM
	binary.BigEndian.PutUint32(prefix[6:10], uint32(len(wrapped.Public)))
	binary.BigEndian.PutUint32(prefix[10:14], uint32(len(wrapped.Private)))
	prefix = append(prefix, wrapped.Public...)
	prefix = append(prefix, wrapped.Private...)
	nonceStart := len(prefix)
	prefix = append(prefix, make([]byte, aead.NonceSize())...)
	nonce := prefix[nonceStart:]
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generating cache nonce: %w", err)
	}

	result := append([]byte(nil), prefix...)
	result = aead.Seal(result, nonce, plaintext, prefix)
	if len(result) > maxCacheEnvelopeSize {
		return nil, fmt.Errorf("TPM credential cache envelope is too large")
	}
	return result, nil
}

func decryptCredentialCache(sealer keySealer, envelope []byte) ([]byte, error) {
	if sealer == nil {
		return nil, fmt.Errorf("TPM credential cache: missing key sealer")
	}
	if len(envelope) < cacheEnvelopeFixedSize || len(envelope) > maxCacheEnvelopeSize || !bytes.Equal(envelope[:4], cacheEnvelopeMagic) {
		return nil, errInvalidCache
	}
	if envelope[4] != cacheEnvelopeVersion || envelope[5] != cacheEnvelopeAES256GCM {
		return nil, errInvalidCache
	}
	publicSize := uint64(binary.BigEndian.Uint32(envelope[6:10]))
	privateSize := uint64(binary.BigEndian.Uint32(envelope[10:14]))
	if publicSize == 0 || publicSize > maxTPMSealedPartSize || privateSize == 0 || privateSize > maxTPMSealedPartSize {
		return nil, errInvalidCache
	}

	// AES-GCM has a 12-byte standard nonce and a 16-byte authentication tag.
	prefixSize := uint64(cacheEnvelopeFixedSize) + publicSize + privateSize + 12
	if prefixSize > uint64(len(envelope)) || uint64(len(envelope))-prefixSize < 16 {
		return nil, errInvalidCache
	}
	publicEnd := cacheEnvelopeFixedSize + int(publicSize)
	privateEnd := publicEnd + int(privateSize)
	prefixEnd := int(prefixSize)
	wrapped := sealedBlob{
		Public:  envelope[cacheEnvelopeFixedSize:publicEnd],
		Private: envelope[publicEnd:privateEnd],
	}

	dekBytes, err := sealer.Unseal(wrapped)
	if err != nil {
		return nil, fmt.Errorf("unsealing cache data key: %w", err)
	}
	defer clear(dekBytes)
	if len(dekBytes) != cacheDEKSize {
		return nil, errInvalidCache
	}
	var dek [cacheDEKSize]byte
	copy(dek[:], dekBytes)
	defer clear(dek[:])
	aead, err := cacheAEAD(dek)
	if err != nil {
		return nil, err
	}
	nonce := envelope[privateEnd:prefixEnd]
	plaintext, err := aead.Open(nil, nonce, envelope[prefixEnd:], envelope[:prefixEnd])
	if err != nil {
		return nil, errInvalidCache
	}
	return plaintext, nil
}

func cacheAEAD(key [cacheDEKSize]byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("creating cache AES cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating cache AES-GCM: %w", err)
	}
	return aead, nil
}
