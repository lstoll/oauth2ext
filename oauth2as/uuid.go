package oauth2as

import (
	"crypto/rand"
	"fmt"
)

func newUUIDv4() string {
	var uuid = make([]byte, 16)
	if n, err := rand.Read(uuid); err != nil || n != 16 {
		panic(fmt.Sprintf("failed to generate random UUID: %v", err))
	}
	uuid[6] = (uuid[6] & 0x0f) | (4 << 4) // Set version to 4
	uuid[8] = (uuid[8] & 0x3f) | 0x80     // Set variant to RFC 4122
	return fmt.Sprintf("%x-%x-%x-%x-%x", uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:16])
}
