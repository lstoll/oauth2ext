package jwt

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/lstoll/oauth2ext/internal/th"
)

func TestCustomMarshaling(t *testing.T) {
	type container struct {
		UnixTime         UnixTime
		StrOrSliceSingle StrOrSlice
		StrOrSliceSlice  StrOrSlice
	}

	c := container{
		UnixTime:         UnixTime(th.Must(time.Parse("2006-Jan-02", "2019-Nov-20")).Unix()),
		StrOrSliceSingle: StrOrSlice([]string{"a"}),
		StrOrSliceSlice:  StrOrSlice([]string{"a", "b"}),
	}

	wantJSON := `{"UnixTime":1574208000,"StrOrSliceSingle":"a","StrOrSliceSlice":["a","b"]}`

	b, err := json.Marshal(&c)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != wantJSON {
		t.Errorf("want %s, got: %s", wantJSON, string(b))
	}

	gc := container{}

	if err := json.Unmarshal([]byte(wantJSON), &gc); err != nil {
		t.Fatal(err)
	}

	if diff := cmp.Diff(c, gc); diff != "" {
		t.Error(diff)
	}
}
