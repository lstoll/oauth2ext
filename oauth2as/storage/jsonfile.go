package storage

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/lstoll/oidcop/internal/jsonfile"
)

var _ Storage = (*JSONFile)(nil)

type JSONFile struct {
	db *jsonfile.JSONFile[jsonFileSchema]
}

func NewJSONFile(path string) (*JSONFile, error) {
	db, err := jsonfile.Load[jsonFileSchema](path)
	if errors.Is(err, os.ErrNotExist) {
		db, err = jsonfile.New[jsonFileSchema](path)
	}
	if err != nil {
		return nil, fmt.Errorf("load/create db: %w", err)
	}
	return &JSONFile{db: db}, nil
}

func (j *JSONFile) GetAuthRequest(ctx context.Context, id uuid.UUID) (*AuthRequest, error) {
	var got *AuthRequest
	j.db.Read(func(data *jsonFileSchema) {
		for _, ar := range data.AuthRequests {
			if ar.ID == id && !time.Now().After(ar.Expiry) {
				got = &ar
				break
			}
		}
	})
	// nil == not found
	return got, nil
}

func (j *JSONFile) PutAuthRequest(ctx context.Context, ar *AuthRequest) error {
	return j.db.Write(func(data *jsonFileSchema) error {
		var updated bool
		for i, gar := range data.AuthRequests {
			if gar.ID == ar.ID {
				data.AuthRequests[i] = *ar
				updated = true
			}
		}
		if !updated {
			data.AuthRequests = append(data.AuthRequests, *ar)
		}
		return nil
	})
}

func (j *JSONFile) DeleteAuthRequest(ctx context.Context, id uuid.UUID) error {
	return j.db.Write(func(data *jsonFileSchema) error {
		data.AuthRequests = slices.DeleteFunc(data.AuthRequests, func(ar AuthRequest) bool {
			return ar.ID == id
		})
		return nil
	})
}

func (j *JSONFile) PutAuthorization(ctx context.Context, a *Authorization) error {
	return j.db.Write(func(data *jsonFileSchema) error {
		var updated bool
		for i, ga := range data.Authorizations {
			if ga.ID == a.ID {
				data.Authorizations[i] = *a
				updated = true
			}
		}
		if !updated {
			data.Authorizations = append(data.Authorizations, *a)
		}
		return nil
	})
}

func (j *JSONFile) GetAuthCode(ctx context.Context, id uuid.UUID) (*AuthCode, *Authorization, error) {
	var (
		gotAc *AuthCode
		gotAn *Authorization
	)
	j.db.Read(func(data *jsonFileSchema) {
		for _, ac := range data.AuthCodes {
			if ac.ID == id && !time.Now().After(ac.Expiry) {
				gotAc = &ac
				break
			}
		}
		if gotAc != nil {
			gotAn = j.getAuthorization(data, gotAc.AuthorizationID)
		}
	})
	// nil == not found
	return gotAc, gotAn, nil
}

func (j *JSONFile) PutAuthCode(ctx context.Context, ac *AuthCode) error {
	return j.db.Write(func(data *jsonFileSchema) error {
		var updated bool
		for i, gac := range data.AuthCodes {
			if gac.ID == ac.ID {
				data.AuthCodes[i] = *ac
				updated = true
			}
		}
		if !updated {
			data.AuthCodes = append(data.AuthCodes, *ac)
		}
		return nil
	})
}

func (j *JSONFile) DeleteAuthCode(ctx context.Context, id uuid.UUID) error {
	return j.db.Write(func(data *jsonFileSchema) error {
		data.AuthCodes = slices.DeleteFunc(data.AuthCodes, func(ac AuthCode) bool {
			return ac.ID == id
		})
		return nil
	})
}

func (j *JSONFile) GetRefreshSession(ctx context.Context, id uuid.UUID) (*RefreshSession, *Authorization, error) {
	var (
		gotRs *RefreshSession
		gotAn *Authorization
	)
	j.db.Read(func(data *jsonFileSchema) {
		for _, rs := range data.RefreshSessions {
			if rs.ID == id && !time.Now().After(rs.Expiry) {
				gotRs = &rs
				break
			}
		}
		if gotRs != nil {
			gotAn = j.getAuthorization(data, gotRs.AuthorizationID)
		}
	})
	// nil == not found
	return gotRs, gotAn, nil
}

func (j *JSONFile) PutRefreshSession(ctx context.Context, rs *RefreshSession) error {
	return j.db.Write(func(data *jsonFileSchema) error {
		var updated bool
		for i, grs := range data.RefreshSessions {
			if grs.ID == rs.ID {
				data.RefreshSessions[i] = *rs
				updated = true
			}
		}
		if !updated {
			data.RefreshSessions = append(data.RefreshSessions, *rs)
		}
		return nil
	})
}

func (j *JSONFile) getAuthorization(data *jsonFileSchema, id uuid.UUID) *Authorization {
	for _, a := range data.Authorizations {
		if a.ID == id {
			return &a
		}
	}
	return nil
}

func (j *JSONFile) DeleteRefreshSession(ctx context.Context, id uuid.UUID) error {
	return j.db.Write(func(data *jsonFileSchema) error {
		data.RefreshSessions = slices.DeleteFunc(data.RefreshSessions, func(rs RefreshSession) bool {
			return rs.ID == id
		})
		return nil
	})
}

type jsonFileSchema struct {
	AuthRequests    []AuthRequest    `json:"authRequests"`
	Authorizations  []Authorization  `json:"authorizations"`
	AuthCodes       []AuthCode       `json:"authCodes"`
	RefreshSessions []RefreshSession `json:"refreshSessions"`
}
