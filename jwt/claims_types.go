package jwt

import (
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"time"
)

// StrOrSlice represents a JWT claim that can either be a single string, or a
// list of strings..
type StrOrSlice []string

// Contains returns true if a passed item is found in the set
func (a StrOrSlice) Contains(s string) bool {
	return slices.Contains(a, s)
}

func (a StrOrSlice) MarshalJSON() ([]byte, error) {
	if len(a) == 1 {
		return json.Marshal(a[0])
	}
	return json.Marshal([]string(a))
}

func (a *StrOrSlice) UnmarshalJSON(b []byte) error {
	var ua any
	if err := json.Unmarshal(b, &ua); err != nil {
		return err
	}

	switch ja := ua.(type) {
	case string:
		*a = []string{ja}
	case []any:
		aa := make([]string, len(ja))
		for i, ia := range ja {
			sa, ok := ia.(string)
			if !ok {
				return fmt.Errorf("failed to unmarshal audience, expected []string but found %T", ia)
			}
			aa[i] = sa
		}
		*a = aa
	default:
		return fmt.Errorf("failed to unmarshal audience, expected string or []string but found %T", ua)
	}

	return nil
}

// UnixTime represents the number representing the number of seconds from
// 1970-01-01T0:0:0Z as measured in UTC until the date/time. This is the type
// IDToken uses to represent dates
type UnixTime int64

// Time returns the *time.Time this represents
func (u UnixTime) Time() time.Time {
	return time.Unix(int64(u), 0)
}

func (u UnixTime) MarshalJSON() ([]byte, error) {
	return []byte(strconv.FormatInt(int64(u), 10)), nil
}

func (u *UnixTime) UnmarshalJSON(b []byte) error {
	flt, err := strconv.ParseFloat(string(b), 64)
	if err != nil {
		return fmt.Errorf("failed to parse UnixTime: %v", err)
	}
	*u = UnixTime(int64(flt))
	return nil
}
