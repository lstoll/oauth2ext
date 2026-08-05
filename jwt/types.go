package jwt

// JSONValue is a non-null value produced when JSON is decoded into any.
// It constrains ArrayOf and HasArrayOf to ordinary Go JSON representations.
type JSONValue interface {
	string | bool | float64 | []any | map[string]any
}
