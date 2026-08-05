package claims

import (
	"time"

	"lds.li/oauth2ext/jwt"
)

// VerifiedID is an OpenID Connect ID token that has passed signature, JWT, and
// ID-token profile validation.
type VerifiedID struct {
	*jwt.VerifiedJWT
}

func (i *VerifiedID) HasName() bool              { return i.HasString("name") }
func (i *VerifiedID) Name() (string, error)      { return i.String("name") }
func (i *VerifiedID) HasGivenName() bool         { return i.HasString("given_name") }
func (i *VerifiedID) GivenName() (string, error) { return i.String("given_name") }
func (i *VerifiedID) HasFamilyName() bool        { return i.HasString("family_name") }
func (i *VerifiedID) FamilyName() (string, error) {
	return i.String("family_name")
}
func (i *VerifiedID) HasMiddleName() bool { return i.HasString("middle_name") }
func (i *VerifiedID) MiddleName() (string, error) {
	return i.String("middle_name")
}
func (i *VerifiedID) HasNickname() bool         { return i.HasString("nickname") }
func (i *VerifiedID) Nickname() (string, error) { return i.String("nickname") }
func (i *VerifiedID) HasPreferredUsername() bool {
	return i.HasString("preferred_username")
}
func (i *VerifiedID) PreferredUsername() (string, error) {
	return i.String("preferred_username")
}
func (i *VerifiedID) HasProfile() bool         { return i.HasString("profile") }
func (i *VerifiedID) Profile() (string, error) { return i.String("profile") }
func (i *VerifiedID) HasPicture() bool         { return i.HasString("picture") }
func (i *VerifiedID) Picture() (string, error) { return i.String("picture") }
func (i *VerifiedID) HasWebsite() bool         { return i.HasString("website") }
func (i *VerifiedID) Website() (string, error) { return i.String("website") }
func (i *VerifiedID) HasEmail() bool           { return i.HasString("email") }
func (i *VerifiedID) Email() (string, error)   { return i.String("email") }
func (i *VerifiedID) HasEmailVerified() bool   { return i.HasBool("email_verified") }
func (i *VerifiedID) EmailVerified() (bool, error) {
	return i.Bool("email_verified")
}
func (i *VerifiedID) HasGender() bool         { return i.HasString("gender") }
func (i *VerifiedID) Gender() (string, error) { return i.String("gender") }
func (i *VerifiedID) HasBirthdate() bool      { return i.HasString("birthdate") }
func (i *VerifiedID) Birthdate() (string, error) {
	return i.String("birthdate")
}
func (i *VerifiedID) HasZoneinfo() bool         { return i.HasString("zoneinfo") }
func (i *VerifiedID) Zoneinfo() (string, error) { return i.String("zoneinfo") }
func (i *VerifiedID) HasLocale() bool           { return i.HasString("locale") }
func (i *VerifiedID) Locale() (string, error)   { return i.String("locale") }
func (i *VerifiedID) HasPhoneNumber() bool      { return i.HasString("phone_number") }
func (i *VerifiedID) PhoneNumber() (string, error) {
	return i.String("phone_number")
}
func (i *VerifiedID) HasPhoneNumberVerified() bool {
	return i.HasBool("phone_number_verified")
}
func (i *VerifiedID) PhoneNumberVerified() (bool, error) {
	return i.Bool("phone_number_verified")
}
func (i *VerifiedID) HasAddress() bool { return i.HasObject("address") }
func (i *VerifiedID) Address() (map[string]any, error) {
	return i.Object("address")
}
func (i *VerifiedID) HasUpdatedAt() bool { return i.HasNumericDate("updated_at") }
func (i *VerifiedID) UpdatedAt() (time.Time, error) {
	return i.NumericDate("updated_at")
}
func (i *VerifiedID) HasACR() bool         { return i.HasString("acr") }
func (i *VerifiedID) ACR() (string, error) { return i.String("acr") }
func (i *VerifiedID) HasAMR() bool         { return i.HasArrayOf[string]("amr") }
func (i *VerifiedID) AMR() ([]string, error) {
	return i.ArrayOf[string]("amr")
}
func (i *VerifiedID) HasAuthTime() bool { return i.HasNumericDate("auth_time") }
func (i *VerifiedID) AuthTime() (time.Time, error) {
	return i.NumericDate("auth_time")
}
func (i *VerifiedID) HasNonce() bool         { return i.HasString("nonce") }
func (i *VerifiedID) Nonce() (string, error) { return i.String("nonce") }
func (i *VerifiedID) HasAuthorizedParty() bool {
	return i.HasString("azp")
}
func (i *VerifiedID) AuthorizedParty() (string, error) {
	return i.String("azp")
}
func (i *VerifiedID) HasAtHash() bool         { return i.HasString("at_hash") }
func (i *VerifiedID) AtHash() (string, error) { return i.String("at_hash") }
func (i *VerifiedID) HasCHash() bool          { return i.HasString("c_hash") }
func (i *VerifiedID) CHash() (string, error)  { return i.String("c_hash") }
func (i *VerifiedID) HasSID() bool            { return i.HasString("sid") }
func (i *VerifiedID) SID() (string, error)    { return i.String("sid") }
