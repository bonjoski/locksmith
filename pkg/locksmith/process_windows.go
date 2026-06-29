//go:build windows
// +build windows

package locksmith

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

func getCallingBinaryPath() (string, error) {
	ppid := os.Getppid()
	if ppid <= 0 {
		return "", fmt.Errorf("invalid parent process ID: %d", ppid)
	}

	// Open the parent process handle with limited query information rights.
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(ppid))
	if err != nil {
		return "", fmt.Errorf("failed to open parent process %d: %w", ppid, err)
	}
	defer windows.CloseHandle(handle)

	var size uint32 = windows.MAX_PATH
	buf := make([]uint16, size)
	err = windows.QueryFullProcessImageName(handle, 0, &buf[0], &size)
	if err != nil {
		return "", fmt.Errorf("failed to query full process image name for %d: %w", ppid, err)
	}

	return windows.UTF16ToString(buf[:size]), nil
}
