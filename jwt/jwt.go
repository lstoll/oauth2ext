package jwt

import (
	"fmt"

	"google.golang.org/protobuf/types/known/structpb"
)

type VerifiedJWT struct {
	token *structpb.Struct
}

func newVerifiedJWT(payload []byte) (*VerifiedJWT, error) {
	var token structpb.Struct
	if err := token.UnmarshalJSON(payload); err != nil {
		return nil, fmt.Errorf("unmarshalling payload: %w", err)
	}
	return &VerifiedJWT{token: &token}, nil
}

func (v *VerifiedJWT) HasStringClaim(name string) bool {
	return v.token.Fields[name] != nil
}
