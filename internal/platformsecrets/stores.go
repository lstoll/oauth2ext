package platformsecrets

import (
	"lds.li/oauth2ext/tokencache"
)

var platformStores = []tokencache.Store{}

// Register registers a platform credential store. This is intended to be
// called by platform specific packages (e.g. tpmsecrets) in their init
// functions. Later registrations are preferred.
func Register(s tokencache.Store) {
	platformStores = append([]tokencache.Store{s}, platformStores...)
}

// Best returns the most preferred available store for the platform and
// environment, or nil if none are available.
func Best() tokencache.Store {
	for _, s := range platformStores {
		if s.Available() {
			return s
		}
	}
	return nil
}
