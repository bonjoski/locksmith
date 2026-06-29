//go:build !locksmith_admin

package locksmith

func (l *Locksmith) checkLazyRotation(key string) {
	// No-op when admin capability is not compiled in
}
