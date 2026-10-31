module lds.li/oauth2ext/tpmsecrets

go 1.27

replace lds.li/oauth2ext => ../

require (
	github.com/google/go-tpm v0.9.8
	golang.org/x/oauth2 v0.36.0
	golang.org/x/sys v0.42.0
	lds.li/oauth2ext v0.0.0-00010101000000-000000000000
)

require (
	github.com/go-jose/go-jose/v4 v4.1.4 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
)
