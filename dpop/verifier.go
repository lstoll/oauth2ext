package dpop

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"maps"
	"time"

	"github.com/tink-crypto/tink-go/v2/jwt"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"google.golang.org/protobuf/types/known/structpb"
)

// DefaultValidityAfterIssue is the default validity after the issue time for a
// DPoP token, if it has no explicit expiry.
const DefaultValidityAfterIssue = 10 * time.Minute

type Verifier struct {
	// ValidityAfterIssue is the validity after the issue time for a DPoP token,
	// if it has no explicit expiry. Defaults to DefaultValidityAfterIssue.
	ValidityAfterIssue time.Duration

	// TrustedRoots, when non-nil, requires a non-empty x5c JWT header. The leaf
	// certificate must chain to one of these roots (per x509.Verify). The JWT
	// signature is verified using the leaf certificate's public key. When nil,
	// verification uses the embedded jwk header only (RFC 9449 default).
	TrustedRoots *x509.CertPool

	now time.Time
}

// Proof is the result of verifying a DPoP token.
type Proof struct {
	// VerifiedJWT is the verified JWT.
	VerifiedJWT *jwt.VerifiedJWT
	// Thumbprint is the JWK thumbprint.
	Thumbprint string
	// CertificateChain is the validated x5c chain (leaf first, then
	// intermediates toward the trust anchor) when [Verifier.TrustedRoots] was
	// set; otherwise nil.
	CertificateChain []*x509.Certificate
}

// ValidatorOpts parameters for DPoP token validation.
type ValidatorOpts struct {
	// ExpectedThumbprint is the expected JWK thumbprint. The token must match
	// this.
	ExpectedThumbprint string
	// IgnoreThumbprint is used to ignore the thumbprint check, this is useful
	// for the initial validation before the thumbprint is bound to the token.
	IgnoreThumbprint bool
	// ExpectedHTM is the expected HTTP method. If set, the htm claim must match.
	ExpectedHTM *string
	// ExpectedHTU is the expected HTTP URI. If set, the htu claim must match.
	ExpectedHTU *string
	// AllowUnsetHTMHTU is used to allow the htm and htu claims to be unset. If
	// this is true, the expected values will only be checked if the claims are
	// set.
	AllowUnsetHTMHTU bool
}

// Validator is used to validate DPoP tokens
type Validator struct {
	opts *ValidatorOpts
}

func NewValidator(opts *ValidatorOpts) (*Validator, error) {
	return &Validator{
		opts: opts,
	}, nil
}

// VerifyAndDecode verifies a DPoP token and returns the verified JWT along with
// the JWK thumbprint.
func (d *Verifier) VerifyAndDecode(compact string, validator *Validator) (*Proof, error) {
	header, err := parseJWTHeader(compact)
	if err != nil {
		return nil, fmt.Errorf("parsing JWT header: %w", err)
	}

	var thumbprint string
	var handle *keyset.Handle
	var certChain []*x509.Certificate

	if d.TrustedRoots != nil {
		thumbprint, handle, certChain, err = d.verifyMaterialFromX5C(header)
	} else {
		thumbprint, handle, err = verifyMaterialFromJWK(header)
	}
	if err != nil {
		return nil, err
	}

	if !validator.opts.IgnoreThumbprint && thumbprint != validator.opts.ExpectedThumbprint {
		return nil, fmt.Errorf("JWK thumbprint mismatch: got %q, want %q", thumbprint, validator.opts.ExpectedThumbprint)
	}

	jwtVerifier, err := jwt.NewVerifier(handle)
	if err != nil {
		return nil, fmt.Errorf("creating tink verifier: %w", err)
	}

	tinkValidator, err := jwt.NewValidator(&jwt.ValidatorOpts{
		ExpectedTypeHeader:     new("dpop+jwt"),
		AllowMissingExpiration: true,
	})
	if err != nil {
		return nil, fmt.Errorf("creating validator: %w", err)
	}

	verifiedJWT, err := jwtVerifier.VerifyAndDecode(compact, tinkValidator)
	if err != nil {
		return nil, fmt.Errorf("verifying JWT: %w", err)
	}

	now := time.Now()
	if !d.now.IsZero() {
		now = d.now
	}

	if !verifiedJWT.HasExpiration() {
		iat, err := verifiedJWT.IssuedAt()
		if err != nil {
			return nil, fmt.Errorf("getting issued at: %w", err)
		}
		vp := d.ValidityAfterIssue
		if vp == 0 {
			vp = DefaultValidityAfterIssue
		}
		if now.After(iat.Add(vp)) {
			return nil, fmt.Errorf("token expired")
		}
	}

	if validator.opts.ExpectedHTM != nil {
		if !verifiedJWT.HasStringClaim("htm") {
			if !validator.opts.AllowUnsetHTMHTU {
				return nil, fmt.Errorf("htm claim missing")
			}
			// If AllowUnsetHTMHTU is true, we allow the claim to be missing
		} else {
			// Claim exists, so we must validate it matches
			htm, err := verifiedJWT.StringClaim("htm")
			if err != nil {
				return nil, fmt.Errorf("getting htm claim: %w", err)
			}
			if htm != *validator.opts.ExpectedHTM {
				return nil, fmt.Errorf("htm claim mismatch: got %q, want %q", htm, *validator.opts.ExpectedHTM)
			}
		}
	}

	if validator.opts.ExpectedHTU != nil {
		if !verifiedJWT.HasStringClaim("htu") {
			if !validator.opts.AllowUnsetHTMHTU {
				return nil, fmt.Errorf("htu claim missing")
			}
			// If AllowUnsetHTMHTU is true, we allow the claim to be missing
		} else {
			// Claim exists, so we must validate it matches
			htu, err := verifiedJWT.StringClaim("htu")
			if err != nil {
				return nil, fmt.Errorf("getting htu claim: %w", err)
			}
			if htu != *validator.opts.ExpectedHTU {
				return nil, fmt.Errorf("htu claim mismatch: got %q, want %q", htu, *validator.opts.ExpectedHTU)
			}
		}
	}

	return &Proof{
		VerifiedJWT:      verifiedJWT,
		Thumbprint:       thumbprint,
		CertificateChain: certChain,
	}, nil
}

func headerAlg(header *structpb.Struct) (string, error) {
	if !hasClaimOfKind(header, "alg", &structpb.Value{Kind: &structpb.Value_StringValue{}}) {
		return "", fmt.Errorf("alg header is missing")
	}
	alg := header.GetFields()["alg"].GetStringValue()
	if alg == "" {
		return "", fmt.Errorf("alg header is empty")
	}
	return alg, nil
}

func keysetHandleFromJWKWithAlg(jwk map[string]any, alg string) (*keyset.Handle, error) {
	jwkForTink := make(map[string]any)
	maps.Copy(jwkForTink, jwk)
	jwkForTink["alg"] = alg
	jwkWithAlgJSON, err := json.Marshal(jwkForTink)
	if err != nil {
		return nil, fmt.Errorf("marshaling jwk with alg: %w", err)
	}
	handle, err := jwt.JWKSetToPublicKeysetHandle(fmt.Appendf(nil, `{"keys":[%s]}`, string(jwkWithAlgJSON)))
	if err != nil {
		return nil, fmt.Errorf("creating keyset handle from JWK: %w", err)
	}
	return handle, nil
}

func verifyMaterialFromJWK(header *structpb.Struct) (thumbprint string, handle *keyset.Handle, err error) {
	if !hasClaimOfKind(header, "jwk", &structpb.Value{Kind: &structpb.Value_StructValue{}}) {
		return "", nil, fmt.Errorf("jwk header is missing")
	}
	jwk := header.GetFields()["jwk"].GetStructValue().AsMap()
	if len(jwk) == 0 {
		return "", nil, fmt.Errorf("jwk header is missing")
	}

	thumbprint, err = calculateJWKThumbprint(jwk)
	if err != nil {
		return "", nil, fmt.Errorf("calculating JWK thumbprint: %w", err)
	}

	alg, err := headerAlg(header)
	if err != nil {
		return "", nil, err
	}

	handle, err = keysetHandleFromJWKWithAlg(jwk, alg)
	if err != nil {
		return "", nil, err
	}

	return thumbprint, handle, nil
}

func (d *Verifier) verifyMaterialFromX5C(header *structpb.Struct) (thumbprint string, handle *keyset.Handle, chain []*x509.Certificate, err error) {
	if !hasClaimOfKind(header, "x5c", &structpb.Value{Kind: &structpb.Value_ListValue{}}) {
		return "", nil, nil, fmt.Errorf("x5c header is required when Verifier.TrustedRoots is set")
	}
	x5c := header.GetFields()["x5c"].GetListValue().AsSlice()
	if len(x5c) == 0 {
		return "", nil, nil, fmt.Errorf("x5c header is missing or empty")
	}

	certChain, err := parseAndVerifyCertChain(d.TrustedRoots, x5c)
	if err != nil {
		return "", nil, nil, fmt.Errorf("verifying certificate chain: %w", err)
	}

	leafCert := certChain[0]
	leafJWK, err := publicKeyToJWK(leafCert.PublicKey)
	if err != nil {
		return "", nil, nil, fmt.Errorf("leaf certificate public key: %w", err)
	}

	thumbprint, err = calculateJWKThumbprint(leafJWK)
	if err != nil {
		return "", nil, nil, fmt.Errorf("calculating JWK thumbprint: %w", err)
	}

	if hasClaimOfKind(header, "jwk", &structpb.Value{Kind: &structpb.Value_StructValue{}}) {
		hdrJWK := header.GetFields()["jwk"].GetStructValue().AsMap()
		if len(hdrJWK) > 0 {
			hdrTP, err := calculateJWKThumbprint(hdrJWK)
			if err != nil {
				return "", nil, nil, fmt.Errorf("calculating header jwk thumbprint: %w", err)
			}
			if hdrTP != thumbprint {
				return "", nil, nil, fmt.Errorf("jwk does not match x5c leaf certificate public key")
			}
		}
	}

	alg, err := headerAlg(header)
	if err != nil {
		return "", nil, nil, err
	}

	handle, err = keysetHandleFromJWKWithAlg(leafJWK, alg)
	if err != nil {
		return "", nil, nil, fmt.Errorf("creating keyset handle from leaf certificate: %w", err)
	}

	return thumbprint, handle, certChain, nil
}

func parseAndVerifyCertChain(roots *x509.CertPool, x5c []any) ([]*x509.Certificate, error) {
	if roots == nil {
		return nil, fmt.Errorf("trusted roots are not set")
	}

	certs := make([]*x509.Certificate, 0, len(x5c))
	for i, certB64 := range x5c {
		certStr, ok := certB64.(string)
		if !ok {
			return nil, fmt.Errorf("x5c[%d] is not a string", i)
		}

		certDER, err := base64.StdEncoding.DecodeString(certStr)
		if err != nil {
			return nil, fmt.Errorf("decoding x5c[%d]: %w", i, err)
		}

		cert, err := x509.ParseCertificate(certDER)
		if err != nil {
			return nil, fmt.Errorf("parsing x5c[%d]: %w", i, err)
		}

		certs = append(certs, cert)
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates in x5c chain")
	}

	leafCert := certs[0]
	intermediates := certs[1:]

	opts := x509.VerifyOptions{
		Intermediates: x509.NewCertPool(),
		Roots:         roots,
	}
	for _, intermediate := range intermediates {
		opts.Intermediates.AddCert(intermediate)
	}

	if _, err := leafCert.Verify(opts); err != nil {
		return nil, fmt.Errorf("certificate chain verification failed: %w", err)
	}

	return certs, nil
}
