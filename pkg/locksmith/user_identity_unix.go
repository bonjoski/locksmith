//go:build !windows
// +build !windows

package locksmith

import (
	"os"
	"strconv"
)

func getSystemUID() string {
	uid := os.Getuid()
	if uid >= 0 {
		return strconv.Itoa(uid)
	}
	return os.Getenv("UID")
}
