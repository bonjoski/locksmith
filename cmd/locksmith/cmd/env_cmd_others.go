//go:build !darwin

package cmd

import (
	"fmt"
	"time"
)

func bootTime() (time.Time, error) {
	return time.Time{}, fmt.Errorf("session cache not supported on this platform")
}
