//go:build windows

package native

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

func getProcessInfo(pid int) (*ProcessInfo, error) {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return nil, fmt.Errorf("failed to open process handle for PID %d: %w", pid, err)
	}
	defer windows.CloseHandle(handle)

	var size uint32 = windows.MAX_PATH
	buf := make([]uint16, size)
	for {
		err = windows.QueryFullProcessImageName(handle, 0, &buf[0], &size)
		if err == nil {
			break
		}
		// Windows error handling for buffer size
		if err == windows.ERROR_INSUFFICIENT_BUFFER {
			size *= 2
			buf = make([]uint16, size)
			continue
		}
		return nil, fmt.Errorf("failed to query process image name for PID %d: %w", pid, err)
	}

	path := windows.UTF16ToString(buf[:size])
	return &ProcessInfo{
		Path:       path,
		Identifier: "",
		TeamID:     "",
	}, nil
}

func getParentPID(pid int) (int, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return -1, fmt.Errorf("failed to create toolhelp snapshot: %w", err)
	}
	defer windows.CloseHandle(snapshot)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	err = windows.Process32First(snapshot, &entry)
	if err != nil {
		return -1, fmt.Errorf("failed to read first process from snapshot: %w", err)
	}

	for {
		if int(entry.ProcessID) == pid {
			return int(entry.ParentProcessID), nil
		}
		err = windows.Process32Next(snapshot, &entry)
		if err != nil {
			break
		}
	}

	return -1, fmt.Errorf("process with PID %d not found in snapshot", pid)
}
