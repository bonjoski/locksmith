//go:build windows

package locksmith

import (
	"os"
	"syscall"
)

var forwardedSignals = []os.Signal{
	syscall.SIGINT,
	syscall.SIGTERM,
}
