package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/format"
	"os"
	"path/filepath"
	"strings"
	"text/template"
)

type Claim struct {
	Claim       string `json:"claim"`
	Method      string `json:"method"`
	Type        string `json:"type"`
	Description string `json:"description"`
}

type Config struct {
	Type        string  `json:"type"`
	Description string  `json:"description,omitempty"`
	Claims      []Claim `json:"claims"`
}

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "usage: %s <config.json> <output.go> [package]\n", os.Args[0])
		os.Exit(1)
	}

	configPath := os.Args[1]
	outputPath := os.Args[2]

	// Determine package name
	var pkgName string
	if len(os.Args) >= 4 {
		pkgName = os.Args[3]
	} else {
		// Derive from output path
		absPath, err := filepath.Abs(outputPath)
		if err == nil {
			dir := filepath.Dir(absPath)
			pkgName = filepath.Base(dir)
		} else {
			// Fallback to simple directory name
			dir := filepath.Dir(outputPath)
			pkgName = filepath.Base(dir)
		}
	}

	if pkgName == "" {
		pkgName = "claims" // default fallback
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading config: %v\n", err)
		os.Exit(1)
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		fmt.Fprintf(os.Stderr, "error parsing config: %v\n", err)
		os.Exit(1)
	}

	tmpl := template.New("claims").Funcs(template.FuncMap{
		"lower":      strings.ToLower,
		"trimPrefix": strings.TrimPrefix,
		"formatComment": func(s string, indent string) string {
			return formatDescription(s, indent)
		},
		"hasCheck":        getHasCheck,
		"returnType":      getReturnType,
		"returnStmt":      getReturnStatement,
		"fieldType":       getFieldType,
		"assignStmt":      getAssignStatement,
		"hasArrayClaim":   hasArrayClaim,
		"reservedVarName": func(t string) string { return fmt.Sprintf("reserved%sClaims", t) },
		"helperName":      func(t string) string { return fmt.Sprintf("isReserved%sClaim", t) },
	})

	tmpl, err = tmpl.Parse(claimsTemplate)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error parsing template: %v\n", err)
		os.Exit(1)
	}

	var buf bytes.Buffer
	type TemplateData struct {
		PkgName string
		Config  Config
	}

	if err := tmpl.Execute(&buf, TemplateData{PkgName: pkgName, Config: config}); err != nil {
		fmt.Fprintf(os.Stderr, "error executing template: %v\n", err)
		os.Exit(1)
	}

	formatted, err := format.Source(buf.Bytes())
	if err != nil {
		fmt.Fprintf(os.Stderr, "error formatting code: %v\n", err)
		// For debugging, print the unformatted code
		// fmt.Println(buf.String())
		os.Exit(1)
	}

	if err := os.WriteFile(outputPath, formatted, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "error writing output: %v\n", err)
		os.Exit(1)
	}
}

func hasArrayClaim(claims []Claim) bool {
	for _, c := range claims {
		if c.Type == "array" {
			return true
		}
	}
	return false
}

func getHasCheck(claimType, constName string) string {
	switch claimType {
	case "string":
		return fmt.Sprintf("i.jwt.HasStringClaim(%s)", constName)
	case "bool":
		return fmt.Sprintf("i.jwt.HasBooleanClaim(%s)", constName)
	case "time":
		return fmt.Sprintf("i.jwt.HasNumberClaim(%s)", constName)
	case "array":
		return fmt.Sprintf("i.jwt.HasArrayClaim(%s)", constName)
	case "object":
		return fmt.Sprintf("i.jwt.HasObjectClaim(%s)", constName)
	default:
		return fmt.Sprintf("i.jwt.HasStringClaim(%s)", constName)
	}
}

func getReturnType(claimType string) string {
	switch claimType {
	case "string":
		return "string"
	case "bool":
		return "bool"
	case "time":
		return "time.Time"
	case "array":
		return "[]any"
	case "object":
		return "map[string]any"
	default:
		return "string"
	}
}

func getReturnStatement(claimType, constName string) string {
	switch claimType {
	case "string":
		return fmt.Sprintf("return i.jwt.StringClaim(%s)", constName)
	case "bool":
		return fmt.Sprintf("return i.jwt.BooleanClaim(%s)", constName)
	case "time":
		return fmt.Sprintf(`ts, err := i.jwt.NumberClaim(%s)
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(int64(ts), 0).UTC(), nil`, constName)
	case "array":
		return fmt.Sprintf("return i.jwt.ArrayClaim(%s)", constName)
	case "object":
		return fmt.Sprintf("return i.jwt.ObjectClaim(%s)", constName)
	default:
		return fmt.Sprintf("return i.jwt.StringClaim(%s)", constName)
	}
}

func getFieldType(claimType string) string {
	switch claimType {
	case "string":
		return "*string"
	case "bool":
		return "*bool"
	case "time":
		return "*time.Time"
	case "array":
		return "[]string"
	case "object":
		return "map[string]any"
	default:
		return "*string"
	}
}

func getAssignStatement(claimType, methodName, constName string) string {
	switch claimType {
	case "string", "bool":
		return fmt.Sprintf("o.CustomClaims[%s] = *r.%s", constName, methodName)
	case "time":
		return fmt.Sprintf("o.CustomClaims[%s] = r.%s.Unix()", constName, methodName)
	case "array":
		// Convert []string to []any for the custom claims map
		return fmt.Sprintf("o.CustomClaims[%s] = convertStringSlice(r.%s)", constName, methodName)
	case "object":
		return fmt.Sprintf("o.CustomClaims[%s] = r.%s", constName, methodName)
	default:
		return fmt.Sprintf("o.CustomClaims[%s] = *r.%s", constName, methodName)
	}
}

func formatDescription(desc string, indent string) string {
	// Account for comment prefix: "// " (3 chars)
	const commentPrefixLen = 3
	const maxTotalLineLength = 100
	maxLineLength := maxTotalLineLength - commentPrefixLen - len(strings.ReplaceAll(indent, "\t", "    "))

	if len(desc) <= maxLineLength {
		return desc
	}

	var result strings.Builder
	words := strings.Fields(desc)
	currentLine := ""

	for _, word := range words {
		// If adding this word would exceed the line length, start a new line
		testLine := currentLine
		if testLine != "" {
			testLine += " "
		}
		testLine += word

		if len(testLine) > maxLineLength && currentLine != "" {
			if result.Len() > 0 {
				result.WriteString("\n")
				result.WriteString(indent)
				result.WriteString("// ")
			}
			result.WriteString(currentLine)
			currentLine = word
		} else {
			if currentLine != "" {
				currentLine += " "
			}
			currentLine += word
		}
	}

	if currentLine != "" {
		if result.Len() > 0 {
			result.WriteString("\n")
			result.WriteString(indent)
			result.WriteString("// ")
		}
		result.WriteString(currentLine)
	}

	return result.String()
}

const claimsTemplate = `// Code generated by o2ext-claimgen. DO NOT EDIT.

package {{.PkgName}}

import (
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/tink-crypto/tink-go/v2/jwt"
)

{{$type := .Config.Type}}
{{$verifiedType := printf "Verified%s" $type}}

// {{$verifiedType}} {{if .Config.Description}}{{formatComment .Config.Description ""}}{{else}}represents the claims of an OIDC {{$type}} token{{end}}
type {{$verifiedType}} struct {
	jwt *jwt.VerifiedJWT
}

// HasIssuer checks whether a JWT contains the issuer claim.
func (i *{{$verifiedType}}) HasIssuer() bool {
	return i.jwt.HasIssuer()
}

// Issuer returns the issuer claim ('iss') or an error if no claim is present.
func (i *{{$verifiedType}}) Issuer() (string, error) {
	return i.jwt.Issuer()
}

// HasSubject checks whether a JWT contains the subject claim.
func (i *{{$verifiedType}}) HasSubject() bool {
	return i.jwt.HasSubject()
}

// Subject returns the subject claim ('sub') or an error if no claim is present.
func (i *{{$verifiedType}}) Subject() (string, error) {
	return i.jwt.Subject()
}

// HasAudiences checks whether a JWT contains the audience claim ('aud').
func (i *{{$verifiedType}}) HasAudiences() bool {
	return i.jwt.HasAudiences()
}

// Audiences returns a list of audiences from the 'aud' claim. If the 'aud' claim is a single
// string, it is converted into a list with a single entry.
func (i *{{$verifiedType}}) Audiences() ([]string, error) {
	return i.jwt.Audiences()
}

// HasJWTID checks whether a JWT contains the jwtid claim.
func (i *{{$verifiedType}}) HasJWTID() bool {
	return i.jwt.HasJWTID()
}

// JWTID returns the JWT ID claim ('jti') or an error if no claim is present.
func (i *{{$verifiedType}}) JWTID() (string, error) {
	return i.jwt.JWTID()
}

// HasIssuedAt checks whether a JWT contains the issuedat claim.
func (i *{{$verifiedType}}) HasIssuedAt() bool {
	return i.jwt.HasIssuedAt()
}

// IssuedAt returns the issued at claim ('iat') or an error if no claim is present.
func (i *{{$verifiedType}}) IssuedAt() (time.Time, error) {
	return i.jwt.IssuedAt()
}

// HasExpiration checks whether a JWT contains the expiration claim.
func (i *{{$verifiedType}}) HasExpiration() bool {
	return i.jwt.HasExpiration()
}

// ExpiresAt returns the expiration claim ('exp') or an error if no claim is present.
func (i *{{$verifiedType}}) ExpiresAt() (time.Time, error) {
	return i.jwt.ExpiresAt()
}

// HasNotBefore checks whether a JWT contains the notbefore claim.
func (i *{{$verifiedType}}) HasNotBefore() bool {
	return i.jwt.HasNotBefore()
}

// NotBefore returns the not before claim ('nbf') or an error if no claim is present.
func (i *{{$verifiedType}}) NotBefore() (time.Time, error) {
	return i.jwt.NotBefore()
}

// JSONPayload marshals a VerifiedJWT payload to JSON.
func (i *{{$verifiedType}}) JSONPayload() ([]byte, error) {
	return i.jwt.JSONPayload()
}

// JWT returns the underlying VerifiedJWT.
func (i *{{$verifiedType}}) JWT() *jwt.VerifiedJWT {
	return i.jwt
}

const (
{{- range .Config.Claims}}
	{{printf "%sClaim%s" ($type | lower) .Method}} = "{{.Claim}}"
{{- end}}
)

{{- range .Config.Claims}}
{{$constName := printf "%sClaim%s" ($type | lower) .Method}}

// Has{{.Method}} checks whether the {{.Claim}} claim is present.
func (i *{{$verifiedType}}) Has{{.Method}}() bool {
	return {{hasCheck .Type $constName}}
}

// {{formatComment (printf "%s returns %s" .Method .Description) ""}}
func (i *{{$verifiedType}}) {{.Method}}() ({{returnType .Type}}, error) {
	{{returnStmt .Type $constName}}
}
{{- end}}

var {{reservedVarName $type}} = []string{
{{- range .Config.Claims}}
	{{printf "%sClaim%s" ($type | lower) .Method}},
{{- end}}
}

// HasStringClaim checks whether a claim of type string is present.
func (i *{{$verifiedType}}) HasStringClaim(name string) bool {
	return i.jwt.HasStringClaim(name)
}

// StringClaim returns a custom string claim or an error if no claim is present.
// Reserved claims should be accessed using their specific methods.
func (i *{{$verifiedType}}) StringClaim(name string) (string, error) {
	if {{helperName $type}}(name) {
		return "", fmt.Errorf("claim %s is reserved", name)
	}
	return i.jwt.StringClaim(name)
}

// HasNumberClaim checks whether a claim of type number is present.
func (i *{{$verifiedType}}) HasNumberClaim(name string) bool {
	return i.jwt.HasNumberClaim(name)
}

// NumberClaim returns a custom number claim or an error if no claim is present.
// Reserved claims should be accessed using their specific methods.
func (i *{{$verifiedType}}) NumberClaim(name string) (float64, error) {
	if {{helperName $type}}(name) {
		return 0, fmt.Errorf("claim %s is reserved", name)
	}
	return i.jwt.NumberClaim(name)
}

// HasBooleanClaim checks whether a claim of type bool is present.
func (i *{{$verifiedType}}) HasBooleanClaim(name string) bool {
	return i.jwt.HasBooleanClaim(name)
}

// BooleanClaim returns a custom bool claim or an error if no claim is present.
// Reserved claims should be accessed using their specific methods.
func (i *{{$verifiedType}}) BooleanClaim(name string) (bool, error) {
	if {{helperName $type}}(name) {
		return false, fmt.Errorf("claim %s is reserved", name)
	}
	return i.jwt.BooleanClaim(name)
}

// HasNullClaim checks whether a claim of type null is present.
func (i *{{$verifiedType}}) HasNullClaim(name string) bool {
	return i.jwt.HasNullClaim(name)
}

// HasArrayClaim checks whether a claim of type list is present.
func (i *{{$verifiedType}}) HasArrayClaim(name string) bool {
	return i.jwt.HasArrayClaim(name)
}

// ArrayClaim returns a slice representing a JSON array for a claim or an error if the claim is empty.
// Reserved claims should be accessed using their specific methods.
func (i *{{$verifiedType}}) ArrayClaim(name string) ([]any, error) {
	if {{helperName $type}}(name) {
		return nil, fmt.Errorf("claim %s is reserved", name)
	}
	return i.jwt.ArrayClaim(name)
}

// HasObjectClaim checks whether a claim of type object is present.
func (i *{{$verifiedType}}) HasObjectClaim(name string) bool {
	return i.jwt.HasObjectClaim(name)
}

// ObjectClaim returns a map representing a JSON object for a claim or an error if the claim is empty.
// Reserved claims should be accessed using their specific methods.
func (i *{{$verifiedType}}) ObjectClaim(name string) (map[string]any, error) {
	if {{helperName $type}}(name) {
		return nil, fmt.Errorf("claim %s is reserved", name)
	}
	return i.jwt.ObjectClaim(name)
}

// CustomClaimNames returns a list with the name of custom claims in a VerifiedJWT.
func (i *{{$verifiedType}}) CustomClaimNames() []string {
	return i.jwt.CustomClaimNames()
}

func {{helperName $type}}(name string) bool {
	return slices.Contains({{reservedVarName $type}}, name)
}

type Raw{{$type}}Options struct {
	Issuer    *string
	ClientID  *string
	Subject   *string
	JWTID     *string
	IssuedAt  *time.Time
	ExpiresAt *time.Time
	NotBefore *time.Time
{{- range .Config.Claims}}
	// {{formatComment (printf "%s is %s" .Method .Description) "\t"}}
	{{.Method}} {{fieldType .Type}}
{{- end}}
	// CustomClaims contains additional custom claims to include in the JWT.
	// These claims will be merged with the standard and extended claims.
	CustomClaims map[string]any
}

func (r *Raw{{$type}}Options) JWTOptions() *jwt.RawJWTOptions {
{{- if hasArrayClaim .Config.Claims}}
	convertStringSlice := func(s []string) []any {
		if s == nil {
			return nil
		}
		result := make([]any, len(s))
		for i, v := range s {
			result[i] = v
		}
		return result
	}

{{end}}
	o := &jwt.RawJWTOptions{
		Issuer:       r.Issuer,
		Audience:     r.ClientID,
		Subject:      r.Subject,
		IssuedAt:     r.IssuedAt,
		ExpiresAt:    r.ExpiresAt,
		NotBefore:    r.NotBefore,
		CustomClaims: maps.Clone(r.CustomClaims),
	}

	if o.CustomClaims == nil {
		o.CustomClaims = make(map[string]any)
	}
{{- range .Config.Claims -}}
{{$constName := printf "%sClaim%s" ($type | lower) .Method}}
	if r.{{.Method}} != nil {
		{{assignStmt .Type .Method $constName}}
	}
{{- end}}

	return o
}
`
