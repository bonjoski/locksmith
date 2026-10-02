//go:build windows
// +build windows

package locksmith

import (
	"os"
)

func getSystemUID() string {
	// On Windows, USERNAME or USERDOMAIN\USERNAME serves as UID fallback if user.Current() was unavailable
	if username := os.Getenv("USERNAME"); username != "" {
		if domain := os.Getenv("USERDOMAIN"); domain != "" {
			return domain + "\\" + username
		}
		return username
	}
	return ""
}
