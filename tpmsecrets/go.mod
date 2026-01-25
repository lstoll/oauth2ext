module lds.li/oauth2ext/tpmsecrets

go 1.25

replace lds.li/oauth2ext => ../

require (
	github.com/google/go-tpm v0.9.3
	github.com/tink-crypto/tink-go/v2 v2.6.0
	golang.org/x/oauth2 v0.34.0
	lds.li/oauth2ext v0.0.0-00010101000000-000000000000
)

require (
	github.com/google/go-cmp v0.7.0 // indirect
	golang.org/x/crypto v0.46.0 // indirect
	golang.org/x/sys v0.39.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)
