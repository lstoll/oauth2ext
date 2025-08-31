package discovery

import (
	"encoding/json"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestSTSKeyOps(t *testing.T) {
	const (
		in   = `{"keys":[{"alg":"RS256","e":"AQAB","key_ops":["verify"],"kid":"Au1Yww","kty":"RSA","n":"wC0LusRYr6twrN1lCu0KZ4sP-JeojS_b2NjPqs959dovRcUELV8teIZFx7CgRt9zRXtqYNe3LVVIM9PLpAzud3WaANRHVN-elpGH4tizDCSps7soEbbvTmvaiYijEl0ObZQztiDxRh9PKrRu10N-C2EXXBgT_qcM_PTyoQHGnzkpwYZwVMj0w8lK4bMcQ_sJkOW4cbqWahSbyhRMY_f4F4zcExG2ZT_GANKgJShA5QCItO74l3kIjVLs-af3OIy3S8OoPYgIWT3FykhP_0H0CAz3XnxuD5iUGGChvRs6jM9t9hGVa8698pCDrITys_sc7l0nFhY1NyoqsInOp83JMw","use":"sig"},{"alg":"RS256","e":"AQAB","key_ops":["verify"],"kid":"TTluRw","kty":"RSA","n":"3vtqKby4O2ya645ILGTI02JWYcUWLLkWiNOWX9VF8pOJHsLunzgpsKWgJQA0d7M08_QejzYBbQKM-5ksjqwX9JK89Y43VxWcSHui0FZ77uRibzElTSQlWq6ONPSNdyLGk24OZIcb9BruV9weIglKGgj1j2t6LUMOq_hwpZtRMS3UDCzkJLMlgHp86CKs9w-caE0HKo9e5R5-XLLO-nX33eVpLgoupdFkO_oTpOjyMgeO000pcdZOGrHDdOa7Y2lQsEga1W1AFmQoqHoTEn8yyzFRW-Y1k-9eaWeDkjSmT4-Fqj4uJdULKvTQXGSk3k9yo_ICAvQCoZ8fvFe9qJmN2Q","use":"sig"},{"alg":"RS256","e":"AQAB","key_ops":["verify"],"kid":"FLKkkQ","kty":"RSA","n":"0twGpi24JF7fU4g-23NEJaoSZGYwaymfPJFaTaBxh-gdnzdmxG6cq1FcWuFJa2QY-RmQAuFG4LKD5QCpB8I04ltfK89aIgF1tu5CUDNWFNg3-tRFe_5g6pwkpZbV0DRfKMfEUBoQ7NOnIcVmUdxVUyAvBUq63XZ3_qPURCXzxDG06GEdFFOOMag-Gdn1gf3omK6QA5RaoZk-CloskGnOTaEvM75McO1EteNzQtDAeEeOtXSEKEez5T2YGXiOt3xbG9Uj-NgCqUWbQLrlD0U3V1UWJQnJ3jYV0wIcI90SEEtE9HgM0IUxmiiUvwYjkUwkWTjYGIbgn6pEkTP021bsHQ","use":"sig"}]}`
		want = `{"keys":[{"alg":"RS256","e":"AQAB","kid":"Au1Yww","kty":"RSA","n":"wC0LusRYr6twrN1lCu0KZ4sP-JeojS_b2NjPqs959dovRcUELV8teIZFx7CgRt9zRXtqYNe3LVVIM9PLpAzud3WaANRHVN-elpGH4tizDCSps7soEbbvTmvaiYijEl0ObZQztiDxRh9PKrRu10N-C2EXXBgT_qcM_PTyoQHGnzkpwYZwVMj0w8lK4bMcQ_sJkOW4cbqWahSbyhRMY_f4F4zcExG2ZT_GANKgJShA5QCItO74l3kIjVLs-af3OIy3S8OoPYgIWT3FykhP_0H0CAz3XnxuD5iUGGChvRs6jM9t9hGVa8698pCDrITys_sc7l0nFhY1NyoqsInOp83JMw","use":"sig"},{"alg":"RS256","e":"AQAB","kid":"TTluRw","kty":"RSA","n":"3vtqKby4O2ya645ILGTI02JWYcUWLLkWiNOWX9VF8pOJHsLunzgpsKWgJQA0d7M08_QejzYBbQKM-5ksjqwX9JK89Y43VxWcSHui0FZ77uRibzElTSQlWq6ONPSNdyLGk24OZIcb9BruV9weIglKGgj1j2t6LUMOq_hwpZtRMS3UDCzkJLMlgHp86CKs9w-caE0HKo9e5R5-XLLO-nX33eVpLgoupdFkO_oTpOjyMgeO000pcdZOGrHDdOa7Y2lQsEga1W1AFmQoqHoTEn8yyzFRW-Y1k-9eaWeDkjSmT4-Fqj4uJdULKvTQXGSk3k9yo_ICAvQCoZ8fvFe9qJmN2Q","use":"sig"},{"alg":"RS256","e":"AQAB","kid":"FLKkkQ","kty":"RSA","n":"0twGpi24JF7fU4g-23NEJaoSZGYwaymfPJFaTaBxh-gdnzdmxG6cq1FcWuFJa2QY-RmQAuFG4LKD5QCpB8I04ltfK89aIgF1tu5CUDNWFNg3-tRFe_5g6pwkpZbV0DRfKMfEUBoQ7NOnIcVmUdxVUyAvBUq63XZ3_qPURCXzxDG06GEdFFOOMag-Gdn1gf3omK6QA5RaoZk-CloskGnOTaEvM75McO1EteNzQtDAeEeOtXSEKEez5T2YGXiOt3xbG9Uj-NgCqUWbQLrlD0U3V1UWJQnJ3jYV0wIcI90SEEtE9HgM0IUxmiiUvwYjkUwkWTjYGIbgn6pEkTP021bsHQ","use":"sig"}]}`
	)

	var (
		wantMap map[string]any
		gotMap  map[string]any
	)
	if err := json.Unmarshal([]byte(want), &wantMap); err != nil {
		t.Fatal(err)
	}

	got, err := stripKeyOps([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(got, &gotMap); err != nil {
		t.Fatal(err)
	}

	if diff := cmp.Diff(wantMap, gotMap); diff != "" {
		t.Error(diff)
	}
}
